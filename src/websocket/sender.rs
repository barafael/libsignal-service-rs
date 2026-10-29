use libsignal_core::{DeviceId, ServiceId};
use libsignal_net_grpc::proto::chat::messages::{
    challenge_required::ChallengeType,
    individual_recipient_message_bundle::Message,
    messages_anonymous_client::MessagesAnonymousClient,
    messages_client::MessagesClient,
    send_message_authenticated_sender_response, send_message_response,
    send_sealed_sender_message_request, ChallengeRequired,
    IndividualRecipientMessageBundle, MismatchedDevices,
    SendAuthenticatedSenderMessageRequest, SendMessageType,
    SendSealedSenderMessageRequest, SendStoryMessageRequest,
    SendSyncMessageRequest,
};

use crate::{
    proto::{envelope, WebSocketRequestMessage},
    push_service::{
        self,
        response::{error_mapper, json_or_unhandled, SignalServiceResponse},
        ProofRequired,
    },
    sender::{OutgoingPushMessage, OutgoingPushMessages, SendMessageResponse},
    unidentified_access::UnidentifiedAccess,
    utils::BASE64_RELAXED,
};

use super::*;
use base64::Engine;

// Signal-Server: controllers/MessageController.java
// (PUT /v1/messages/multi_recipient)
error_mapper! {
    put_multi_recipient_messages_errors:
        // 409: mismatched devices
        CONFLICT => fn multi_recipient_mismatched_devices,
        // 410: stale devices
        GONE => fn multi_recipient_stale_devices,
        // 428: proof required
        PRECONDITION_REQUIRED => ProofRequiredError(crate::push_service::ProofRequired),
}

impl<C: WebSocketType> SignalWebSocket<C> {
    pub async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let urgent = messages.urgent;
        let (destination, ephemeral, messages) = messages.into_parts()?;
        let response = MessagesClient::new(self.grpc.authenticated()?)
            .send_message(SendAuthenticatedSenderMessageRequest {
                destination: Some(destination.into()),
                ephemeral,
                urgent,
                messages: Some(messages),
            })
            .await?
            .into_inner();
        authenticated_sender_response(response.response)
    }

    /// Sends a message to the other devices linked to our own account.
    pub async fn send_sync_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let urgent = messages.urgent;
        let (_destination, _ephemeral, messages) = messages.into_parts()?;
        let response = MessagesClient::new(self.grpc.authenticated()?)
            .send_sync_message(SendSyncMessageRequest {
                urgent,
                messages: Some(messages),
            })
            .await?
            .into_inner();
        authenticated_sender_response(response.response)
    }

    pub async fn send_messages_unidentified(
        &mut self,
        messages: OutgoingPushMessages,
        access: &UnidentifiedAccess,
    ) -> Result<SendMessageResponse, ServiceError> {
        use send_message_response::Response;

        let story = messages.story;
        let urgent = messages.urgent;
        let (destination, ephemeral, messages) = messages.into_parts()?;
        let mut client =
            MessagesAnonymousClient::new(self.grpc.unauthenticated());
        let response = if story {
            client
                .send_story(SendStoryMessageRequest {
                    destination: Some(destination.into()),
                    urgent,
                    messages: Some(messages),
                })
                .await?
        } else {
            client
                .send_single_recipient_message(SendSealedSenderMessageRequest {
                    destination: Some(destination.into()),
                    ephemeral,
                    urgent,
                    messages: Some(messages),
                    authorization: Some(
                        send_sealed_sender_message_request::Authorization::UnidentifiedAccessKey(
                            access.key.clone(),
                        ),
                    ),
                })
                .await?
        }
        .into_inner();
        match response.response {
            Some(Response::Success(())) => {
                Ok(SendMessageResponse { needs_sync: false })
            },
            Some(Response::MismatchedDevices(m)) => {
                Err(ServiceError::mismatched_devices(m)?)
            },
            Some(Response::FailedUnidentifiedAuthorization(_)) => {
                Err(ServiceError::Unauthorized)
            },
            Some(Response::DestinationNotFound(_)) => {
                Err(ServiceError::UnregisteredRecipient)
            },
            None => Err(ServiceError::empty_send_response()),
        }
    }
}

fn authenticated_sender_response(
    response: Option<send_message_authenticated_sender_response::Response>,
) -> Result<SendMessageResponse, ServiceError> {
    use send_message_authenticated_sender_response::Response;
    match response {
        Some(Response::Success(())) => {
            Ok(SendMessageResponse { needs_sync: false })
        },
        Some(Response::MismatchedDevices(m)) => {
            Err(ServiceError::mismatched_devices(m)?)
        },
        Some(Response::ChallengeRequired(c)) => Err(
            ServiceError::ProofRequiredError(ProofRequired::from_challenge(c)),
        ),
        Some(Response::DestinationNotFound(_)) => {
            Err(ServiceError::UnregisteredRecipient)
        },
        None => Err(ServiceError::empty_send_response()),
    }
}

impl ServiceError {
    fn empty_send_response() -> Self {
        ServiceError::InvalidFrame {
            reason: "empty send message response",
        }
    }

    // Stale devices come bundled with missing/extra ones; the sender's retry picks them up next round.
    fn mismatched_devices(m: MismatchedDevices) -> Result<Self, Self> {
        let device_ids = |ids: Vec<u32>| {
            ids.into_iter()
                .map(DeviceId::try_from)
                .collect::<Result<Vec<_>, _>>()
        };
        if m.missing_devices.is_empty() && m.extra_devices.is_empty() {
            Ok(ServiceError::StaleDevices(push_service::StaleDevices {
                stale_devices: device_ids(m.stale_devices)?,
            }))
        } else {
            Ok(ServiceError::MismatchedDevicesException(
                push_service::MismatchedDevices {
                    missing_devices: device_ids(m.missing_devices)?,
                    extra_devices: device_ids(m.extra_devices)?,
                },
            ))
        }
    }
}

impl ProofRequired {
    fn from_challenge(c: ChallengeRequired) -> Self {
        let options = c
            .challenge_options()
            .filter_map(|o| match o {
                ChallengeType::Captcha => Some("captcha".to_owned()),
                ChallengeType::PushChallenge => {
                    Some("pushChallenge".to_owned())
                },
                ChallengeType::Unspecified => None,
            })
            .collect();
        Self {
            token: c.token,
            options,
        }
    }
}

impl OutgoingPushMessages {
    fn into_parts(
        self,
    ) -> Result<(ServiceId, bool, IndividualRecipientMessageBundle), ServiceError>
    {
        let OutgoingPushMessages {
            destination,
            timestamp,
            messages,
            online,
            urgent: _,
            story: _,
        } = self;
        let messages = messages
            .into_iter()
            .map(|message| {
                let OutgoingPushMessage {
                    r#type,
                    destination_device_id,
                    destination_registration_id,
                    content,
                } = message;
                let r#type = match envelope::Type::try_from(r#type as i32) {
                    Ok(envelope::Type::DoubleRatchet) => {
                        SendMessageType::DoubleRatchet
                    },
                    Ok(envelope::Type::PrekeyMessage) => {
                        SendMessageType::PrekeyMessage
                    },
                    Ok(envelope::Type::UnidentifiedSender) => {
                        SendMessageType::UnidentifiedSender
                    },
                    Ok(envelope::Type::PlaintextContent) => {
                        SendMessageType::PlaintextContent
                    },
                    _ => {
                        return Err(ServiceError::InvalidFrame {
                            reason: "unsupported outgoing message type",
                        })
                    },
                };
                Ok((
                    u8::from(destination_device_id).into(),
                    Message {
                        registration_id: destination_registration_id,
                        payload: BASE64_RELAXED.decode(content)?,
                        r#type: r#type.into(),
                    },
                ))
            })
            .collect::<Result<_, _>>()?;
        Ok((
            destination,
            online,
            IndividualRecipientMessageBundle {
                timestamp,
                messages,
            },
        ))
    }
}

impl<C: WebSocketType> SignalWebSocket<C> {
    /// One message sealed for many devices
    /// (`sealed_sender_multi_recipient_encrypt`): `PUT
    /// /v1/messages/multi_recipient`. `access_key` is the recipients' access
    /// keys combined (XOR); a story goes without one.
    pub async fn send_multi_recipient(
        &mut self,
        body: Vec<u8>,
        access_key: Option<[u8; 16]>,
        timestamp: u64,
        online: bool,
        urgent: bool,
        story: bool,
    ) -> Result<MultiRecipientResponse, ServiceError> {
        let mut request = WebSocketRequestMessage::new(Method::PUT)
            .path(format!(
                "/v1/messages/multi_recipient?ts={timestamp}&online={online}&urgent={urgent}&story={story}"
            ))
            .header("content-type", "application/vnd.signal-messenger.mrm");
        if let Some(key) = access_key {
            request = request
                .header("Unidentified-Access-Key", BASE64_RELAXED.encode(key));
        }
        let mut request = request.build();
        request.body = Some(body);
        self.request(request)
            .await?
            .service_error_for_status_with(put_multi_recipient_messages_errors)
            .await?
            .json()
            .await
    }
}

/// What the server answers a multi-recipient send: the recipients it doesn't
/// know.
#[derive(Debug, serde::Deserialize)]
pub struct MultiRecipientResponse {
    #[serde(default)]
    pub uuids404: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountDevicesBody {
    uuid: String,
    devices: DevicesBody,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevicesBody {
    #[serde(default)]
    missing_devices: Vec<u32>,
    #[serde(default)]
    extra_devices: Vec<u32>,
    #[serde(default)]
    stale_devices: Vec<u32>,
}

fn device_ids(ids: Vec<u32>) -> Result<Vec<DeviceId>, ServiceError> {
    ids.into_iter()
        .map(|id| {
            DeviceId::try_from(id).map_err(|_| ServiceError::InvalidFrame {
                reason: "device id out of range",
            })
        })
        .collect()
}

fn account_service_id(uuid: &str) -> Result<ServiceId, ServiceError> {
    ServiceId::parse_from_service_id_string(uuid).ok_or(
        ServiceError::InvalidFrame {
            reason: "invalid service id in a multi-recipient response",
        },
    )
}

async fn multi_recipient_mismatched_devices<R>(response: R) -> ServiceError
where
    R: SignalServiceResponse,
    ServiceError: From<<R as SignalServiceResponse>::Error>,
{
    let accounts =
        match json_or_unhandled::<R, Vec<AccountDevicesBody>>(response).await {
            Ok(accounts) => accounts,
            Err(error) => return error,
        };
    let accounts = accounts.into_iter().map(|account| {
        Ok(push_service::AccountMismatchedDevices {
            uuid: account_service_id(&account.uuid)?,
            devices: push_service::MismatchedDevices {
                missing_devices: device_ids(account.devices.missing_devices)?,
                extra_devices: device_ids(account.devices.extra_devices)?,
            },
        })
    });
    match accounts.collect() {
        Ok(accounts) => ServiceError::MultiRecipientMismatchedDevices(accounts),
        Err(error) => error,
    }
}

async fn multi_recipient_stale_devices<R>(response: R) -> ServiceError
where
    R: SignalServiceResponse,
    ServiceError: From<<R as SignalServiceResponse>::Error>,
{
    let accounts =
        match json_or_unhandled::<R, Vec<AccountDevicesBody>>(response).await {
            Ok(accounts) => accounts,
            Err(error) => return error,
        };
    let accounts = accounts.into_iter().map(|account| {
        Ok(push_service::AccountStaleDevices {
            uuid: account_service_id(&account.uuid)?,
            devices: push_service::StaleDevices {
                stale_devices: device_ids(account.devices.stale_devices)?,
            },
        })
    });
    match accounts.collect() {
        Ok(accounts) => ServiceError::MultiRecipientStaleDevices(accounts),
        Err(error) => error,
    }
}
