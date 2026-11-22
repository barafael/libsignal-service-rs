use crate::{
    push_service::response::error_mapper,
    sender::{OutgoingPushMessages, SendMessageResponse},
    unidentified_access::UnidentifiedAccess,
    utils::BASE64_RELAXED,
};

use super::*;
use base64::Engine;

// Signal-Server: controllers/MessageController.java:198
// (PUT /v1/messages/{destination})
error_mapper! {
    put_messages_errors:
        // 409: mismatched devices, MessageController.java:426
        CONFLICT => MismatchedDevicesException(crate::push_service::MismatchedDevices),
        // 410: stale devices, MessageController.java:421
        GONE => StaleDevices(crate::push_service::StaleDevices),
        // 413: message too large, MessageController.java:433
        PAYLOAD_TOO_LARGE => MessageTooLarge,
        // 404: unregistered recipient, MessageController.java:316
        NOT_FOUND => UnregisteredRecipient,
        // 428: proof required, MessageController.java:365
        PRECONDITION_REQUIRED => ProofRequiredError(crate::push_service::ProofRequired),
}

// Signal-Server: controllers/MessageController.java:466
// (PUT /v1/messages/multi_recipient)
error_mapper! {
    put_multi_recipient_messages_errors:
        // 409: mismatched devices, MessageController.java:670
        CONFLICT => MultiRecipientMismatchedDevices(Vec<crate::push_service::AccountMismatchedDevices>),
        // 410: stale devices, MessageController.java:685
        GONE => MultiRecipientStaleDevices(Vec<crate::push_service::AccountStaleDevices>),
        // 413: message too large, MessageController.java:660
        PAYLOAD_TOO_LARGE => MessageTooLarge,
        // 428: proof required, MessageController.java:638
        PRECONDITION_REQUIRED => ProofRequiredError(crate::push_service::ProofRequired),
}

impl<C: WebSocketType> SignalWebSocket<C> {
    pub async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(messages.path())
            .json(&messages)?;
        self.request_json_with(request, put_messages_errors).await
    }

    pub async fn send_messages_unidentified(
        &mut self,
        messages: OutgoingPushMessages,
        access: &UnidentifiedAccess,
    ) -> Result<SendMessageResponse, ServiceError> {
        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(messages.path())
            .header(
                "Unidentified-Access-Key",
                BASE64_RELAXED.encode(&access.key),
            )
            .json(&messages)?;
        self.request_json_with(request, put_messages_errors).await
    }

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
        self.request_json_with(request, put_multi_recipient_messages_errors)
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
