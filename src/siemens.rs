use std::fmt;

/// S7 Protocol Data Unit Types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PduType {
    Job = 0x01,      // Job request
    Ack = 0x02,      // Acknowledgment
    AckData = 0x03,  // Acknowledgment with data
    UserData = 0x07, // User data
}

impl TryFrom<u8> for PduType {
    type Error = S7Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PduType::Job),
            0x02 => Ok(PduType::Ack),
            0x03 => Ok(PduType::AckData),
            0x07 => Ok(PduType::UserData),
            _ => Err(S7Error::InvalidPduType),
        }
    }
}

/// S7 Function Codes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FunctionCode {
    CpuServices = 0x00,
    SetupCommunication = 0xF0,
    ReadVar = 0x04,
    WriteVar = 0x05,
    RequestDownload = 0x1A,
    Download = 0x1B,
    DownloadEnded = 0x1C,
    StartUpload = 0x1D,
    Upload = 0x1E,
    EndUpload = 0x1F,
    PlcControl = 0x28,
    PlcStop = 0x29,
}

impl TryFrom<u8> for FunctionCode {
    type Error = S7Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(FunctionCode::CpuServices),
            0xF0 => Ok(FunctionCode::SetupCommunication),
            0x04 => Ok(FunctionCode::ReadVar),
            0x05 => Ok(FunctionCode::WriteVar),
            0x1A => Ok(FunctionCode::RequestDownload),
            0x1B => Ok(FunctionCode::Download),
            0x1C => Ok(FunctionCode::DownloadEnded),
            0x1D => Ok(FunctionCode::StartUpload),
            0x1E => Ok(FunctionCode::Upload),
            0x1F => Ok(FunctionCode::EndUpload),
            0x28 => Ok(FunctionCode::PlcControl),
            0x29 => Ok(FunctionCode::PlcStop),
            _ => Err(S7Error::InvalidFunctionCode),
        }
    }
}

/// S7 Area Types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum AreaType {
    SystemInfo = 0x03,
    SystemFlags = 0x05,
    AnalogInputs = 0x06,
    AnalogOutputs = 0x07,
    Counters = 0x1C,
    Timers = 0x1D,
    HighSpeedCounters = 0x1F,
    DirectPeripheralAccess = 0x80,
    Inputs = 0x81,
    Outputs = 0x82,
    Flags = 0x83,
    DataBlocks = 0x84,
    InstanceDataBlocks = 0x85,
    LocalData = 0x86,
    Unknown = 0x87,
}

impl TryFrom<u8> for AreaType {
    type Error = S7Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x03 => Ok(AreaType::SystemInfo),
            0x05 => Ok(AreaType::SystemFlags),
            0x06 => Ok(AreaType::AnalogInputs),
            0x07 => Ok(AreaType::AnalogOutputs),
            0x1C => Ok(AreaType::Counters),
            0x1D => Ok(AreaType::Timers),
            0x1F => Ok(AreaType::HighSpeedCounters),
            0x80 => Ok(AreaType::DirectPeripheralAccess),
            0x81 => Ok(AreaType::Inputs),
            0x82 => Ok(AreaType::Outputs),
            0x83 => Ok(AreaType::Flags),
            0x84 => Ok(AreaType::DataBlocks),
            0x85 => Ok(AreaType::InstanceDataBlocks),
            0x86 => Ok(AreaType::LocalData),
            0x87 => Ok(AreaType::Unknown),
            _ => Err(S7Error::InvalidAreaType),
        }
    }
}

/// S7 Data Transport Sizes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TransportSize {
    Null = 0x00,
    Bit = 0x01,
    Byte = 0x02,
    Char = 0x03,
    Word = 0x04,
    Int = 0x05,
    DWord = 0x06,
    DInt = 0x07,
    Real = 0x08,
    Date = 0x09,
    TimeOfDay = 0x0A,
    Time = 0x0B,
    S5Time = 0x0C,
    DateAndTime = 0x0F,
    Counter = 0x1C,
    Timer = 0x1D,
    IecCounter = 0x1E,
    IecTimer = 0x1F,
    HsCounter = 0x20,
}

impl TryFrom<u8> for TransportSize {
    type Error = S7Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(TransportSize::Null),
            0x01 => Ok(TransportSize::Bit),
            0x02 => Ok(TransportSize::Byte),
            0x03 => Ok(TransportSize::Char),
            0x04 => Ok(TransportSize::Word),
            0x05 => Ok(TransportSize::Int),
            0x06 => Ok(TransportSize::DWord),
            0x07 => Ok(TransportSize::DInt),
            0x08 => Ok(TransportSize::Real),
            0x09 => Ok(TransportSize::Date),
            0x0A => Ok(TransportSize::TimeOfDay),
            0x0B => Ok(TransportSize::Time),
            0x0C => Ok(TransportSize::S5Time),
            0x0F => Ok(TransportSize::DateAndTime),
            0x1C => Ok(TransportSize::Counter),
            0x1D => Ok(TransportSize::Timer),
            0x1E => Ok(TransportSize::IecCounter),
            0x1F => Ok(TransportSize::IecTimer),
            0x20 => Ok(TransportSize::HsCounter),
            _ => Err(S7Error::InvalidTransportSize),
        }
    }
}

/// S7 Header structure
#[derive(Debug, Clone, PartialEq)]
pub struct S7Header {
    pub protocol_id: u8,
    pub pdu_type: PduType,
    pub reserved: u16,
    pub pdu_reference: u16,
    pub parameter_length: u16,
    pub data_length: u16,
}

/// S7 Setup Communication Parameters
#[derive(Debug, Clone, PartialEq)]
pub struct SetupCommunication {
    pub function_code: FunctionCode,
    pub reserved: u8,
    pub max_amq_calling: u16,
    pub max_amq_called: u16,
    pub pdu_length: u16,
}

/// S7 Read/Write Variable Request Item
#[derive(Debug, Clone, PartialEq)]
pub struct S7RequestItem {
    pub specification_type: u8,
    pub length_of_following: u8,
    pub syntax_id: u8,
    pub transport_size: TransportSize,
    pub length: u16,
    pub db_number: u16,
    pub area: AreaType,
    pub address: u32, // Bit address (byte_offset * 8 + bit_offset)
}

/// S7 Read Variable Request
#[derive(Debug, Clone, PartialEq)]
pub struct ReadVarRequest {
    pub header: S7Header,
    pub function_code: FunctionCode,
    pub item_count: u8,
    pub items: Vec<S7RequestItem>,
}

/// S7 Write Variable Request
#[derive(Debug, Clone, PartialEq)]
pub struct WriteVarRequest {
    pub header: S7Header,
    pub function_code: FunctionCode,
    pub item_count: u8,
    pub items: Vec<S7RequestItem>,
    pub data: Vec<u8>,
}

/// S7 Response Data Item
#[derive(Debug, Clone, PartialEq)]
pub struct S7ResponseItem {
    pub return_code: u8,
    pub transport_size: TransportSize,
    pub length: u16,
    pub data: Vec<u8>,
}

/// S7 Read Variable Response
#[derive(Debug, Clone, PartialEq)]
pub struct ReadVarResponse {
    pub header: S7Header,
    pub function_code: FunctionCode,
    pub item_count: u8,
    pub items: Vec<S7ResponseItem>,
}

/// S7 parsing errors
#[derive(Debug, PartialEq)]
pub enum S7Error {
    InvalidPduType,
    InvalidFunctionCode,
    InvalidAreaType,
    InvalidTransportSize,
    BufferTooShort,
    InvalidLength,
    InvalidProtocolId,
    InvalidItemCount,
}

impl fmt::Display for S7Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            S7Error::InvalidPduType => write!(f, "Invalid S7 PDU type"),
            S7Error::InvalidFunctionCode => write!(f, "Invalid S7 function code"),
            S7Error::InvalidAreaType => write!(f, "Invalid S7 area type"),
            S7Error::InvalidTransportSize => write!(f, "Invalid S7 transport size"),
            S7Error::BufferTooShort => write!(f, "Buffer too short for S7 message"),
            S7Error::InvalidLength => write!(f, "Invalid length field"),
            S7Error::InvalidProtocolId => write!(f, "Invalid S7 protocol ID"),
            S7Error::InvalidItemCount => write!(f, "Invalid item count"),
        }
    }
}

impl std::error::Error for S7Error {}

/// Parse S7 header
pub fn parse_s7_header(buffer: &[u8]) -> Result<S7Header, S7Error> {
    if buffer.len() < 10 {
        return Err(S7Error::BufferTooShort);
    }

    let protocol_id = buffer[0];
    if protocol_id != 0x32 {
        return Err(S7Error::InvalidProtocolId);
    }

    let pdu_type = PduType::try_from(buffer[1])?;
    let reserved = u16::from_be_bytes([buffer[2], buffer[3]]);
    let pdu_reference = u16::from_be_bytes([buffer[4], buffer[5]]);
    let parameter_length = u16::from_be_bytes([buffer[6], buffer[7]]);
    let data_length = u16::from_be_bytes([buffer[8], buffer[9]]);

    Ok(S7Header {
        protocol_id,
        pdu_type,
        reserved,
        pdu_reference,
        parameter_length,
        data_length,
    })
}

/// Parse Setup Communication request
pub fn parse_setup_communication(buffer: &[u8]) -> Result<SetupCommunication, S7Error> {
    let header = parse_s7_header(buffer)?;

    if header.pdu_type != PduType::Job {
        return Err(S7Error::InvalidPduType);
    }

    if buffer.len() < 18 {
        return Err(S7Error::BufferTooShort);
    }

    let function_code = FunctionCode::try_from(buffer[10])?;
    if function_code != FunctionCode::SetupCommunication {
        return Err(S7Error::InvalidFunctionCode);
    }

    let reserved = buffer[11];
    let max_amq_calling = u16::from_be_bytes([buffer[12], buffer[13]]);
    let max_amq_called = u16::from_be_bytes([buffer[14], buffer[15]]);
    let pdu_length = u16::from_be_bytes([buffer[16], buffer[17]]);

    Ok(SetupCommunication {
        function_code,
        reserved,
        max_amq_calling,
        max_amq_called,
        pdu_length,
    })
}

/// Parse S7 request item
fn parse_request_item(buffer: &[u8], offset: &mut usize) -> Result<S7RequestItem, S7Error> {
    if *offset + 12 > buffer.len() {
        return Err(S7Error::BufferTooShort);
    }

    let specification_type = buffer[*offset];
    let length_of_following = buffer[*offset + 1];
    let syntax_id = buffer[*offset + 2];
    let transport_size = TransportSize::try_from(buffer[*offset + 3])?;
    let length = u16::from_be_bytes([buffer[*offset + 4], buffer[*offset + 5]]);
    let db_number = u16::from_be_bytes([buffer[*offset + 6], buffer[*offset + 7]]);
    let area = AreaType::try_from(buffer[*offset + 8])?;

    // Address is 3 bytes in big-endian format
    let address = u32::from_be_bytes([
        0,
        buffer[*offset + 9],
        buffer[*offset + 10],
        buffer[*offset + 11],
    ]);

    *offset += 12;

    Ok(S7RequestItem {
        specification_type,
        length_of_following,
        syntax_id,
        transport_size,
        length,
        db_number,
        area,
        address,
    })
}

/// Parse Read Variable request
pub fn parse_read_var_request(buffer: &[u8]) -> Result<ReadVarRequest, S7Error> {
    let header = parse_s7_header(buffer)?;

    if header.pdu_type != PduType::Job {
        return Err(S7Error::InvalidPduType);
    }

    if buffer.len() < 12 {
        return Err(S7Error::BufferTooShort);
    }

    let function_code = FunctionCode::try_from(buffer[10])?;
    if function_code != FunctionCode::ReadVar {
        return Err(S7Error::InvalidFunctionCode);
    }

    let item_count = buffer[11];
    let mut offset = 12;
    let mut items = Vec::new();

    for _ in 0..item_count {
        let item = parse_request_item(buffer, &mut offset)?;
        items.push(item);
    }

    Ok(ReadVarRequest {
        header,
        function_code,
        item_count,
        items,
    })
}

/// Parse Read Variable response
pub fn parse_read_var_response(buffer: &[u8]) -> Result<ReadVarResponse, S7Error> {
    let header = parse_s7_header(buffer)?;

    if header.pdu_type != PduType::AckData {
        return Err(S7Error::InvalidPduType);
    }

    if buffer.len() < 12 {
        return Err(S7Error::BufferTooShort);
    }

    let function_code = FunctionCode::try_from(buffer[10])?;
    if function_code != FunctionCode::ReadVar {
        return Err(S7Error::InvalidFunctionCode);
    }

    let item_count = buffer[11];
    let mut offset = 12;
    let mut items = Vec::new();

    for _ in 0..item_count {
        if offset + 4 > buffer.len() {
            return Err(S7Error::BufferTooShort);
        }

        let return_code = buffer[offset];
        let transport_size = TransportSize::try_from(buffer[offset + 1])?;
        let length = u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]);
        offset += 4;

        // Calculate data length in bytes
        let data_length = if transport_size == TransportSize::Bit {
            (length + 7) / 8 // Round up to nearest byte
        } else {
            length
        } as usize;

        if offset + data_length > buffer.len() {
            return Err(S7Error::BufferTooShort);
        }

        let data = buffer[offset..offset + data_length].to_vec();
        offset += data_length;

        // Align to even byte boundary
        if offset % 2 != 0 {
            offset += 1;
        }

        items.push(S7ResponseItem {
            return_code,
            transport_size,
            length,
            data,
        });
    }

    Ok(ReadVarResponse {
        header,
        function_code,
        item_count,
        items,
    })
}

/// Create S7 header
pub fn create_s7_header(
    pdu_type: PduType,
    pdu_reference: u16,
    parameter_length: u16,
    data_length: u16,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    buffer.push(0x32); // Protocol ID
    buffer.push(pdu_type as u8);
    buffer.extend_from_slice(&0u16.to_be_bytes()); // Reserved
    buffer.extend_from_slice(&pdu_reference.to_be_bytes());
    buffer.extend_from_slice(&parameter_length.to_be_bytes());
    buffer.extend_from_slice(&data_length.to_be_bytes());

    buffer
}

/// Create Setup Communication request
pub fn create_setup_communication_request(
    pdu_reference: u16,
    max_amq_calling: u16,
    max_amq_called: u16,
    pdu_length: u16,
) -> Vec<u8> {
    let mut buffer = create_s7_header(PduType::Job, pdu_reference, 8, 0);

    buffer.push(FunctionCode::SetupCommunication as u8);
    buffer.push(0x00); // Reserved
    buffer.extend_from_slice(&max_amq_calling.to_be_bytes());
    buffer.extend_from_slice(&max_amq_called.to_be_bytes());
    buffer.extend_from_slice(&pdu_length.to_be_bytes());

    buffer
}

/// Create Read Variable request
pub fn create_read_var_request(pdu_reference: u16, items: &[S7RequestItem]) -> Vec<u8> {
    let parameter_length = 2 + (items.len() * 12) as u16;
    let mut buffer = create_s7_header(PduType::Job, pdu_reference, parameter_length, 0);

    buffer.push(FunctionCode::ReadVar as u8);
    buffer.push(items.len() as u8);

    for item in items {
        buffer.push(item.specification_type);
        buffer.push(item.length_of_following);
        buffer.push(item.syntax_id);
        buffer.push(item.transport_size as u8);
        buffer.extend_from_slice(&item.length.to_be_bytes());
        buffer.extend_from_slice(&item.db_number.to_be_bytes());
        buffer.push(item.area as u8);

        // Address as 3 bytes
        let addr_bytes = item.address.to_be_bytes();
        buffer.extend_from_slice(&addr_bytes[1..4]);
    }

    buffer
}

/// Create simple S7 request item for reading
pub fn create_read_request_item(
    area: AreaType,
    db_number: u16,
    start_address: u32,
    length: u16,
    transport_size: TransportSize,
) -> S7RequestItem {
    S7RequestItem {
        specification_type: 0x12,
        length_of_following: 0x0A,
        syntax_id: 0x10,
        transport_size,
        length,
        db_number,
        area,
        address: start_address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s7_header() {
        let buffer = vec![
            0x32, // Protocol ID
            0x01, // PDU Type (Job)
            0x00, 0x00, // Reserved
            0x00, 0x01, // PDU Reference
            0x00, 0x08, // Parameter Length
            0x00, 0x00, // Data Length
        ];

        let result = parse_s7_header(&buffer);
        assert!(result.is_ok());

        let header = result.unwrap();
        assert_eq!(header.protocol_id, 0x32);
        assert_eq!(header.pdu_type, PduType::Job);
        assert_eq!(header.pdu_reference, 1);
        assert_eq!(header.parameter_length, 8);
        assert_eq!(header.data_length, 0);
    }

    #[test]
    fn test_parse_s7_header_invalid_protocol() {
        let buffer = vec![
            0x33, // Invalid Protocol ID
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
        ];

        let result = parse_s7_header(&buffer);
        assert_eq!(result, Err(S7Error::InvalidProtocolId));
    }

    #[test]
    fn test_parse_s7_header_buffer_too_short() {
        let buffer = vec![0x32, 0x01, 0x00]; // Too short

        let result = parse_s7_header(&buffer);
        assert_eq!(result, Err(S7Error::BufferTooShort));
    }

    #[test]
    fn test_create_and_parse_setup_communication() {
        let setup_buffer = create_setup_communication_request(1, 1, 1, 240);

        let result = parse_setup_communication(&setup_buffer);
        assert!(result.is_ok());

        let setup = result.unwrap();
        assert_eq!(setup.function_code, FunctionCode::SetupCommunication);
        assert_eq!(setup.max_amq_calling, 1);
        assert_eq!(setup.max_amq_called, 1);
        assert_eq!(setup.pdu_length, 240);
    }

    #[test]
    fn test_pdu_type_conversion() {
        assert_eq!(PduType::try_from(0x01).unwrap(), PduType::Job);
        assert_eq!(PduType::try_from(0x02).unwrap(), PduType::Ack);
        assert_eq!(PduType::try_from(0x03).unwrap(), PduType::AckData);
        assert_eq!(PduType::try_from(0x07).unwrap(), PduType::UserData);
        assert_eq!(PduType::try_from(0xFF), Err(S7Error::InvalidPduType));
    }

    #[test]
    fn test_function_code_conversion() {
        assert_eq!(
            FunctionCode::try_from(0xF0).unwrap(),
            FunctionCode::SetupCommunication
        );
        assert_eq!(FunctionCode::try_from(0x04).unwrap(), FunctionCode::ReadVar);
        assert_eq!(
            FunctionCode::try_from(0x05).unwrap(),
            FunctionCode::WriteVar
        );
        assert_eq!(
            FunctionCode::try_from(0xFF),
            Err(S7Error::InvalidFunctionCode)
        );
    }

    #[test]
    fn test_area_type_conversion() {
        assert_eq!(AreaType::try_from(0x81).unwrap(), AreaType::Inputs);
        assert_eq!(AreaType::try_from(0x82).unwrap(), AreaType::Outputs);
        assert_eq!(AreaType::try_from(0x83).unwrap(), AreaType::Flags);
        assert_eq!(AreaType::try_from(0x84).unwrap(), AreaType::DataBlocks);
        assert_eq!(AreaType::try_from(0xFF), Err(S7Error::InvalidAreaType));
    }

    #[test]
    fn test_transport_size_conversion() {
        assert_eq!(TransportSize::try_from(0x01).unwrap(), TransportSize::Bit);
        assert_eq!(TransportSize::try_from(0x02).unwrap(), TransportSize::Byte);
        assert_eq!(TransportSize::try_from(0x04).unwrap(), TransportSize::Word);
        assert_eq!(TransportSize::try_from(0x06).unwrap(), TransportSize::DWord);
        assert_eq!(
            TransportSize::try_from(0xFF),
            Err(S7Error::InvalidTransportSize)
        );
    }

    #[test]
    fn test_create_read_request_item() {
        let item = create_read_request_item(
            AreaType::DataBlocks,
            1,  // DB1
            0,  // Start address 0
            10, // Length 10
            TransportSize::Byte,
        );

        assert_eq!(item.area, AreaType::DataBlocks);
        assert_eq!(item.db_number, 1);
        assert_eq!(item.address, 0);
        assert_eq!(item.length, 10);
        assert_eq!(item.transport_size, TransportSize::Byte);
    }

    #[test]
    fn test_create_and_parse_read_var_request() {
        let items = vec![
            create_read_request_item(AreaType::DataBlocks, 1, 0, 10, TransportSize::Byte),
            create_read_request_item(AreaType::Flags, 0, 0, 1, TransportSize::Bit),
        ];

        let request_buffer = create_read_var_request(1, &items);

        let result = parse_read_var_request(&request_buffer);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert_eq!(request.header.pdu_type, PduType::Job);
        assert_eq!(request.function_code, FunctionCode::ReadVar);
        assert_eq!(request.item_count, 2);
        assert_eq!(request.items.len(), 2);

        assert_eq!(request.items[0].area, AreaType::DataBlocks);
        assert_eq!(request.items[0].db_number, 1);
        assert_eq!(request.items[0].length, 10);

        assert_eq!(request.items[1].area, AreaType::Flags);
        assert_eq!(request.items[1].transport_size, TransportSize::Bit);
    }

    #[test]
    fn test_parse_read_var_response() {
        // Create a mock response buffer
        let mut buffer = create_s7_header(PduType::AckData, 1, 2, 14);
        buffer.push(FunctionCode::ReadVar as u8);
        buffer.push(1); // Item count

        // Response item
        buffer.push(0xFF); // Return code (success)
        buffer.push(TransportSize::Byte as u8);
        buffer.extend_from_slice(&10u16.to_be_bytes()); // Length
        buffer.extend_from_slice(&vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        ]); // Data

        let result = parse_read_var_response(&buffer);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.header.pdu_type, PduType::AckData);
        assert_eq!(response.function_code, FunctionCode::ReadVar);
        assert_eq!(response.item_count, 1);
        assert_eq!(response.items.len(), 1);

        let item = &response.items[0];
        assert_eq!(item.return_code, 0xFF);
        assert_eq!(item.transport_size, TransportSize::Byte);
        assert_eq!(item.length, 10);
        assert_eq!(
            item.data,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
        );
    }

    #[test]
    fn test_complete_s7_read_transaction() {
        // Create read request
        let items = vec![create_read_request_item(
            AreaType::DataBlocks,
            1,
            0,
            4,
            TransportSize::Byte,
        )];
        let request_buffer = create_read_var_request(1, &items);

        // Parse request
        let request = parse_read_var_request(&request_buffer).unwrap();
        assert_eq!(request.header.pdu_reference, 1);
        assert_eq!(request.items[0].area, AreaType::DataBlocks);
        assert_eq!(request.items[0].db_number, 1);
        assert_eq!(request.items[0].length, 4);

        // Create mock response
        let mut response_buffer = create_s7_header(PduType::AckData, 1, 2, 8);
        response_buffer.push(FunctionCode::ReadVar as u8);
        response_buffer.push(1); // Item count
        response_buffer.push(0xFF); // Return code
        response_buffer.push(TransportSize::Byte as u8);
        response_buffer.extend_from_slice(&4u16.to_be_bytes());
        response_buffer.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Parse response
        let response = parse_read_var_response(&response_buffer).unwrap();
        assert_eq!(response.header.pdu_reference, 1);
        assert_eq!(response.items[0].data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", S7Error::InvalidPduType),
            "Invalid S7 PDU type"
        );
        assert_eq!(
            format!("{}", S7Error::BufferTooShort),
            "Buffer too short for S7 message"
        );
        assert_eq!(
            format!("{}", S7Error::InvalidProtocolId),
            "Invalid S7 protocol ID"
        );
    }
}
