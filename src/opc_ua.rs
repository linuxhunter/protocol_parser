use std::fmt;

/// OPC-UA Message Types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Hello = b'H',
    Acknowledge = b'A',
    Error = b'E',
    ReverseHello = b'R',
    Message = b'M',
    OpenSecureChannel = b'O',
    CloseSecureChannel = b'C',
}

impl TryFrom<[u8; 3]> for MessageType {
    type Error = OpcUaError;

    fn try_from(bytes: [u8; 3]) -> Result<Self, <MessageType as TryFrom<[u8; 3]>>::Error> {
        match &bytes {
            b"HEL" => Ok(MessageType::Hello),
            b"ACK" => Ok(MessageType::Acknowledge),
            b"ERR" => Ok(MessageType::Error),
            b"RHE" => Ok(MessageType::ReverseHello),
            b"MSG" => Ok(MessageType::Message),
            b"OPN" => Ok(MessageType::OpenSecureChannel),
            b"CLO" => Ok(MessageType::CloseSecureChannel),
            _ => Err(OpcUaError::InvalidMessageType),
        }
    }
}

/// OPC-UA Chunk Types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChunkType {
    Final,
    Intermediate,
    Abort,
}

impl TryFrom<u8> for ChunkType {
    type Error = OpcUaError;

    fn try_from(byte: u8) -> Result<Self, <ChunkType as TryFrom<u8>>::Error> {
        match byte {
            b'F' => Ok(ChunkType::Final),
            b'C' => Ok(ChunkType::Intermediate),
            b'A' => Ok(ChunkType::Abort),
            _ => Err(OpcUaError::InvalidChunkType),
        }
    }
}

/// OPC-UA Security Policy URIs
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityPolicy {
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
    Aes128Sha256RsaOaep,
    Aes256Sha256RsaPss,
    Custom(String),
}

/// OPC-UA Message Header
#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeader {
    pub message_type: MessageType,
    pub chunk_type: ChunkType,
    pub message_size: u32,
}

/// OPC-UA Hello Message
#[derive(Debug, Clone, PartialEq)]
pub struct HelloMessage {
    pub header: MessageHeader,
    pub version: u32,
    pub receive_buffer_size: u32,
    pub send_buffer_size: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
    pub endpoint_url: String,
}

/// OPC-UA Acknowledge Message
#[derive(Debug, Clone, PartialEq)]
pub struct AcknowledgeMessage {
    pub header: MessageHeader,
    pub version: u32,
    pub receive_buffer_size: u32,
    pub send_buffer_size: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
}

/// OPC-UA Error Message
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorMessage {
    pub header: MessageHeader,
    pub error_code: u32,
    pub reason: String,
}

/// OPC-UA Secure Channel Message
#[derive(Debug, Clone, PartialEq)]
pub struct SecureChannelMessage {
    pub header: MessageHeader,
    pub secure_channel_id: u32,
    pub security_policy_uri: String,
    pub sender_certificate: Vec<u8>,
    pub receiver_certificate_thumbprint: Vec<u8>,
}

/// OPC-UA parsing errors
#[derive(Debug, PartialEq)]
pub enum OpcUaError {
    InvalidMessageType,
    InvalidChunkType,
    BufferTooShort,
    InvalidLength,
    InvalidVersion,
    InvalidString,
    InvalidSecurityPolicy,
}

impl fmt::Display for OpcUaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpcUaError::InvalidMessageType => write!(f, "Invalid OPC-UA message type"),
            OpcUaError::InvalidChunkType => write!(f, "Invalid OPC-UA chunk type"),
            OpcUaError::BufferTooShort => write!(f, "Buffer too short for OPC-UA message"),
            OpcUaError::InvalidLength => write!(f, "Invalid length field"),
            OpcUaError::InvalidVersion => write!(f, "Invalid OPC-UA version"),
            OpcUaError::InvalidString => write!(f, "Invalid string encoding"),
            OpcUaError::InvalidSecurityPolicy => write!(f, "Invalid security policy"),
        }
    }
}

impl std::error::Error for OpcUaError {}

/// Parse OPC-UA message header
pub fn parse_message_header(buffer: &[u8]) -> Result<MessageHeader, OpcUaError> {
    if buffer.len() < 8 {
        return Err(OpcUaError::BufferTooShort);
    }

    let message_type_bytes = [buffer[0], buffer[1], buffer[2]];
    let message_type = MessageType::try_from(message_type_bytes)?;

    let chunk_type = ChunkType::try_from(buffer[3])?;

    let message_size = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

    Ok(MessageHeader {
        message_type,
        chunk_type,
        message_size,
    })
}

/// Parse OPC-UA string (length-prefixed UTF-8)
fn parse_opc_ua_string(buffer: &[u8], offset: &mut usize) -> Result<String, OpcUaError> {
    if *offset + 4 > buffer.len() {
        return Err(OpcUaError::BufferTooShort);
    }

    let length = i32::from_le_bytes([
        buffer[*offset],
        buffer[*offset + 1],
        buffer[*offset + 2],
        buffer[*offset + 3],
    ]);
    *offset += 4;

    if length == -1 {
        return Ok(String::new()); // Null string
    }

    if length < 0 || *offset + length as usize > buffer.len() {
        return Err(OpcUaError::InvalidString);
    }

    let string_bytes = &buffer[*offset..*offset + length as usize];
    *offset += length as usize;

    String::from_utf8(string_bytes.to_vec()).map_err(|_| OpcUaError::InvalidString)
}

/// Parse OPC-UA byte string (length-prefixed bytes)
fn parse_opc_ua_byte_string(buffer: &[u8], offset: &mut usize) -> Result<Vec<u8>, OpcUaError> {
    if *offset + 4 > buffer.len() {
        return Err(OpcUaError::BufferTooShort);
    }

    let length = i32::from_le_bytes([
        buffer[*offset],
        buffer[*offset + 1],
        buffer[*offset + 2],
        buffer[*offset + 3],
    ]);
    *offset += 4;

    if length == -1 {
        return Ok(Vec::new()); // Null byte string
    }

    if length < 0 || *offset + length as usize > buffer.len() {
        return Err(OpcUaError::InvalidLength);
    }

    let bytes = buffer[*offset..*offset + length as usize].to_vec();
    *offset += length as usize;

    Ok(bytes)
}

/// Parse OPC-UA Hello message
pub fn parse_hello_message(buffer: &[u8]) -> Result<HelloMessage, OpcUaError> {
    let header = parse_message_header(buffer)?;

    if header.message_type != MessageType::Hello {
        return Err(OpcUaError::InvalidMessageType);
    }

    if buffer.len() < header.message_size as usize {
        return Err(OpcUaError::BufferTooShort);
    }

    let mut offset = 8; // Skip header

    if offset + 20 > buffer.len() {
        return Err(OpcUaError::BufferTooShort);
    }

    let version = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let receive_buffer_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let send_buffer_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let max_message_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let max_chunk_count = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let endpoint_url = parse_opc_ua_string(buffer, &mut offset)?;

    Ok(HelloMessage {
        header,
        version,
        receive_buffer_size,
        send_buffer_size,
        max_message_size,
        max_chunk_count,
        endpoint_url,
    })
}

/// Parse OPC-UA Acknowledge message
pub fn parse_acknowledge_message(buffer: &[u8]) -> Result<AcknowledgeMessage, OpcUaError> {
    let header = parse_message_header(buffer)?;

    if header.message_type != MessageType::Acknowledge {
        return Err(OpcUaError::InvalidMessageType);
    }

    if buffer.len() < header.message_size as usize {
        return Err(OpcUaError::BufferTooShort);
    }

    let mut offset = 8; // Skip header

    if offset + 20 > buffer.len() {
        return Err(OpcUaError::BufferTooShort);
    }

    let version = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let receive_buffer_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let send_buffer_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let max_message_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let max_chunk_count = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    Ok(AcknowledgeMessage {
        header,
        version,
        receive_buffer_size,
        send_buffer_size,
        max_message_size,
        max_chunk_count,
    })
}

/// Parse OPC-UA Error message
pub fn parse_error_message(buffer: &[u8]) -> Result<ErrorMessage, OpcUaError> {
    let header = parse_message_header(buffer)?;

    if header.message_type != MessageType::Error {
        return Err(OpcUaError::InvalidMessageType);
    }

    if buffer.len() < header.message_size as usize {
        return Err(OpcUaError::BufferTooShort);
    }

    let mut offset = 8; // Skip header

    if offset + 4 > buffer.len() {
        return Err(OpcUaError::BufferTooShort);
    }

    let error_code = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;

    let reason = parse_opc_ua_string(buffer, &mut offset)?;

    Ok(ErrorMessage {
        header,
        error_code,
        reason,
    })
}

/// Create OPC-UA Hello message
pub fn create_hello_message(
    version: u32,
    receive_buffer_size: u32,
    send_buffer_size: u32,
    max_message_size: u32,
    max_chunk_count: u32,
    endpoint_url: &str,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Message type and chunk type
    buffer.extend_from_slice(b"HELF");

    // Calculate message size (header + body)
    let endpoint_url_bytes = endpoint_url.as_bytes();
    let message_size = 8 + 20 + 4 + endpoint_url_bytes.len() as u32;
    buffer.extend_from_slice(&message_size.to_le_bytes());

    // Body
    buffer.extend_from_slice(&version.to_le_bytes());
    buffer.extend_from_slice(&receive_buffer_size.to_le_bytes());
    buffer.extend_from_slice(&send_buffer_size.to_le_bytes());
    buffer.extend_from_slice(&max_message_size.to_le_bytes());
    buffer.extend_from_slice(&max_chunk_count.to_le_bytes());

    // Endpoint URL (length-prefixed string)
    buffer.extend_from_slice(&(endpoint_url_bytes.len() as i32).to_le_bytes());
    buffer.extend_from_slice(endpoint_url_bytes);

    buffer
}

/// Create OPC-UA Acknowledge message
pub fn create_acknowledge_message(
    version: u32,
    receive_buffer_size: u32,
    send_buffer_size: u32,
    max_message_size: u32,
    max_chunk_count: u32,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Message type and chunk type
    buffer.extend_from_slice(b"ACKF");

    // Message size (header + body)
    let message_size: u32 = 8 + 20;
    buffer.extend_from_slice(&message_size.to_le_bytes());

    // Body
    buffer.extend_from_slice(&version.to_le_bytes());
    buffer.extend_from_slice(&receive_buffer_size.to_le_bytes());
    buffer.extend_from_slice(&send_buffer_size.to_le_bytes());
    buffer.extend_from_slice(&max_message_size.to_le_bytes());
    buffer.extend_from_slice(&max_chunk_count.to_le_bytes());

    buffer
}

/// Create OPC-UA Error message
pub fn create_error_message(error_code: u32, reason: &str) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Message type and chunk type
    buffer.extend_from_slice(b"ERRF");

    // Calculate message size
    let reason_bytes = reason.as_bytes();
    let message_size = 8 + 4 + 4 + reason_bytes.len() as u32;
    buffer.extend_from_slice(&message_size.to_le_bytes());

    // Body
    buffer.extend_from_slice(&error_code.to_le_bytes());

    // Reason string (length-prefixed)
    buffer.extend_from_slice(&(reason_bytes.len() as i32).to_le_bytes());
    buffer.extend_from_slice(reason_bytes);

    buffer
}

/// Validate OPC-UA security policy URI
pub fn parse_security_policy(uri: &str) -> SecurityPolicy {
    match uri {
        "http://opcfoundation.org/UA/SecurityPolicy#None" => SecurityPolicy::None,
        "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15" => SecurityPolicy::Basic128Rsa15,
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256" => SecurityPolicy::Basic256,
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256" => {
            SecurityPolicy::Basic256Sha256
        }
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep" => {
            SecurityPolicy::Aes128Sha256RsaOaep
        }
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss" => {
            SecurityPolicy::Aes256Sha256RsaPss
        }
        _ => SecurityPolicy::Custom(uri.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message_header() {
        let buffer = vec![
            b'H', b'E', b'L', b'F', // Message type: HEL, Chunk type: F
            0x20, 0x00, 0x00, 0x00, // Message size: 32
        ];

        let result = parse_message_header(&buffer);
        assert!(result.is_ok());

        let header = result.unwrap();
        assert_eq!(header.message_type, MessageType::Hello);
        assert_eq!(header.chunk_type, ChunkType::Final);
        assert_eq!(header.message_size, 32);
    }

    #[test]
    fn test_parse_message_header_invalid_type() {
        let buffer = vec![
            b'X', b'Y', b'Z', b'F', // Invalid message type
            0x20, 0x00, 0x00, 0x00,
        ];

        let result = parse_message_header(&buffer);
        assert_eq!(result, Err(OpcUaError::InvalidMessageType));
    }

    #[test]
    fn test_parse_message_header_buffer_too_short() {
        let buffer = vec![b'H', b'E', b'L']; // Too short

        let result = parse_message_header(&buffer);
        assert_eq!(result, Err(OpcUaError::BufferTooShort));
    }

    #[test]
    fn test_create_and_parse_hello_message() {
        let endpoint_url = "opc.tcp://localhost:4840";
        let hello_buffer = create_hello_message(
            0,        // version
            65536,    // receive_buffer_size
            65536,    // send_buffer_size
            16777216, // max_message_size
            0,        // max_chunk_count
            endpoint_url,
        );

        let result = parse_hello_message(&hello_buffer);
        assert!(result.is_ok());

        let hello = result.unwrap();
        assert_eq!(hello.header.message_type, MessageType::Hello);
        assert_eq!(hello.header.chunk_type, ChunkType::Final);
        assert_eq!(hello.version, 0);
        assert_eq!(hello.receive_buffer_size, 65536);
        assert_eq!(hello.send_buffer_size, 65536);
        assert_eq!(hello.max_message_size, 16777216);
        assert_eq!(hello.max_chunk_count, 0);
        assert_eq!(hello.endpoint_url, endpoint_url);
    }

    #[test]
    fn test_create_and_parse_acknowledge_message() {
        let ack_buffer = create_acknowledge_message(
            0,        // version
            65536,    // receive_buffer_size
            65536,    // send_buffer_size
            16777216, // max_message_size
            0,        // max_chunk_count
        );

        let result = parse_acknowledge_message(&ack_buffer);
        assert!(result.is_ok());

        let ack = result.unwrap();
        assert_eq!(ack.header.message_type, MessageType::Acknowledge);
        assert_eq!(ack.header.chunk_type, ChunkType::Final);
        assert_eq!(ack.version, 0);
        assert_eq!(ack.receive_buffer_size, 65536);
        assert_eq!(ack.send_buffer_size, 65536);
        assert_eq!(ack.max_message_size, 16777216);
        assert_eq!(ack.max_chunk_count, 0);
    }

    #[test]
    fn test_create_and_parse_error_message() {
        let error_reason = "Bad connection";
        let error_buffer = create_error_message(0x80010000, error_reason);

        let result = parse_error_message(&error_buffer);
        assert!(result.is_ok());

        let error = result.unwrap();
        assert_eq!(error.header.message_type, MessageType::Error);
        assert_eq!(error.header.chunk_type, ChunkType::Final);
        assert_eq!(error.error_code, 0x80010000);
        assert_eq!(error.reason, error_reason);
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::try_from(*b"HEL").unwrap(), MessageType::Hello);
        assert_eq!(
            MessageType::try_from(*b"ACK").unwrap(),
            MessageType::Acknowledge
        );
        assert_eq!(MessageType::try_from(*b"ERR").unwrap(), MessageType::Error);
        assert_eq!(
            MessageType::try_from(*b"MSG").unwrap(),
            MessageType::Message
        );
        assert_eq!(
            MessageType::try_from(*b"OPN").unwrap(),
            MessageType::OpenSecureChannel
        );
        assert_eq!(
            MessageType::try_from(*b"CLO").unwrap(),
            MessageType::CloseSecureChannel
        );
        assert_eq!(
            MessageType::try_from(*b"XYZ"),
            Err(OpcUaError::InvalidMessageType)
        );
    }

    #[test]
    fn test_chunk_type_conversion() {
        assert_eq!(ChunkType::try_from(b'F').unwrap(), ChunkType::Final);
        assert_eq!(ChunkType::try_from(b'C').unwrap(), ChunkType::Intermediate);
        assert_eq!(ChunkType::try_from(b'A').unwrap(), ChunkType::Abort);
        assert_eq!(ChunkType::try_from(b'X'), Err(OpcUaError::InvalidChunkType));
    }

    #[test]
    fn test_security_policy_parsing() {
        assert_eq!(
            parse_security_policy("http://opcfoundation.org/UA/SecurityPolicy#None"),
            SecurityPolicy::None
        );
        assert_eq!(
            parse_security_policy("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"),
            SecurityPolicy::Basic256Sha256
        );
        assert_eq!(
            parse_security_policy("custom://policy"),
            SecurityPolicy::Custom("custom://policy".to_string())
        );
    }

    #[test]
    fn test_hello_message_with_empty_endpoint() {
        let hello_buffer = create_hello_message(0, 65536, 65536, 16777216, 0, "");

        let result = parse_hello_message(&hello_buffer);
        assert!(result.is_ok());

        let hello = result.unwrap();
        assert_eq!(hello.endpoint_url, "");
    }

    #[test]
    fn test_error_message_with_empty_reason() {
        let error_buffer = create_error_message(0x80010000, "");

        let result = parse_error_message(&error_buffer);
        assert!(result.is_ok());

        let error = result.unwrap();
        assert_eq!(error.reason, "");
    }

    #[test]
    fn test_parse_hello_wrong_message_type() {
        let ack_buffer = create_acknowledge_message(0, 65536, 65536, 16777216, 0);

        let result = parse_hello_message(&ack_buffer);
        assert_eq!(result, Err(OpcUaError::InvalidMessageType));
    }

    #[test]
    fn test_complete_opc_ua_handshake() {
        // Client sends Hello
        let hello_buffer =
            create_hello_message(0, 65536, 65536, 16777216, 0, "opc.tcp://localhost:4840");

        let hello = parse_hello_message(&hello_buffer).unwrap();
        assert_eq!(hello.header.message_type, MessageType::Hello);
        assert_eq!(hello.endpoint_url, "opc.tcp://localhost:4840");

        // Server responds with Acknowledge
        let ack_buffer = create_acknowledge_message(
            0,
            hello.receive_buffer_size,
            hello.send_buffer_size,
            hello.max_message_size,
            hello.max_chunk_count,
        );

        let ack = parse_acknowledge_message(&ack_buffer).unwrap();
        assert_eq!(ack.header.message_type, MessageType::Acknowledge);
        assert_eq!(ack.version, hello.version);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", OpcUaError::InvalidMessageType),
            "Invalid OPC-UA message type"
        );
        assert_eq!(
            format!("{}", OpcUaError::BufferTooShort),
            "Buffer too short for OPC-UA message"
        );
    }
}
