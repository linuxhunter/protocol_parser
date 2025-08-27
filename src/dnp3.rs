/// DNP3 Application Layer Function Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dnp3FunctionCode {
    Confirm = 0x00,
    Read = 0x01,
    Write = 0x02,
    Select = 0x03,
    Operate = 0x04,
    DirectOperate = 0x05,
    DirectOperateNoAck = 0x06,
    ImmediateFreeze = 0x07,
    ImmediateFreezeNoAck = 0x08,
    FreezeClear = 0x09,
    FreezeClearNoAck = 0x0A,
    FreezeAtTime = 0x0B,
    FreezeAtTimeNoAck = 0x0C,
    ColdRestart = 0x0D,
    WarmRestart = 0x0E,
    InitializeData = 0x0F,
    InitializeApplication = 0x10,
    StartApplication = 0x11,
    StopApplication = 0x12,
    SaveConfiguration = 0x13,
    EnableUnsolicited = 0x14,
    DisableUnsolicited = 0x15,
    AssignClass = 0x16,
    DelayMeasure = 0x17,
    RecordCurrentTime = 0x18,
    OpenFile = 0x19,
    CloseFile = 0x1A,
    DeleteFile = 0x1B,
    GetFileInfo = 0x1C,
    AuthenticateFile = 0x1D,
    AbortFile = 0x1E,
    Response = 0x81,
    UnsolicitedResponse = 0x82,
    AuthenticationResponse = 0x83,
}

/// DNP3 Internal Indication Flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dnp3InternalIndications {
    pub broadcast: bool,
    pub class_1_events: bool,
    pub class_2_events: bool,
    pub class_3_events: bool,
    pub need_time: bool,
    pub local_control: bool,
    pub device_trouble: bool,
    pub device_restart: bool,
    pub no_func_code_support: bool,
    pub object_unknown: bool,
    pub parameter_error: bool,
    pub event_buffer_overflow: bool,
    pub already_executing: bool,
    pub config_corrupt: bool,
    pub reserved_2: bool,
    pub reserved_1: bool,
}

/// DNP3 Application Layer Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnp3ApplicationHeader {
    pub application_control: u8,
    pub function_code: Dnp3FunctionCode,
    pub internal_indications: Option<Dnp3InternalIndications>,
}

/// DNP3 Object Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnp3ObjectHeader {
    pub group: u8,
    pub variation: u8,
    pub qualifier: u8,
    pub range_field: Vec<u8>,
}

/// DNP3 Application Layer Message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnp3ApplicationMessage {
    pub header: Dnp3ApplicationHeader,
    pub objects: Vec<Dnp3ObjectHeader>,
    pub data: Vec<u8>,
}

/// DNP3 parsing errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dnp3ParseError {
    InsufficientData,
    InvalidFunctionCode(u8),
    InvalidObjectHeader,
    InvalidQualifier(u8),
    DataCorruption,
}

impl From<u8> for Dnp3FunctionCode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Dnp3FunctionCode::Confirm,
            0x01 => Dnp3FunctionCode::Read,
            0x02 => Dnp3FunctionCode::Write,
            0x03 => Dnp3FunctionCode::Select,
            0x04 => Dnp3FunctionCode::Operate,
            0x05 => Dnp3FunctionCode::DirectOperate,
            0x06 => Dnp3FunctionCode::DirectOperateNoAck,
            0x07 => Dnp3FunctionCode::ImmediateFreeze,
            0x08 => Dnp3FunctionCode::ImmediateFreezeNoAck,
            0x09 => Dnp3FunctionCode::FreezeClear,
            0x0A => Dnp3FunctionCode::FreezeClearNoAck,
            0x0B => Dnp3FunctionCode::FreezeAtTime,
            0x0C => Dnp3FunctionCode::FreezeAtTimeNoAck,
            0x0D => Dnp3FunctionCode::ColdRestart,
            0x0E => Dnp3FunctionCode::WarmRestart,
            0x0F => Dnp3FunctionCode::InitializeData,
            0x10 => Dnp3FunctionCode::InitializeApplication,
            0x11 => Dnp3FunctionCode::StartApplication,
            0x12 => Dnp3FunctionCode::StopApplication,
            0x13 => Dnp3FunctionCode::SaveConfiguration,
            0x14 => Dnp3FunctionCode::EnableUnsolicited,
            0x15 => Dnp3FunctionCode::DisableUnsolicited,
            0x16 => Dnp3FunctionCode::AssignClass,
            0x17 => Dnp3FunctionCode::DelayMeasure,
            0x18 => Dnp3FunctionCode::RecordCurrentTime,
            0x19 => Dnp3FunctionCode::OpenFile,
            0x1A => Dnp3FunctionCode::CloseFile,
            0x1B => Dnp3FunctionCode::DeleteFile,
            0x1C => Dnp3FunctionCode::GetFileInfo,
            0x1D => Dnp3FunctionCode::AuthenticateFile,
            0x1E => Dnp3FunctionCode::AbortFile,
            0x81 => Dnp3FunctionCode::Response,
            0x82 => Dnp3FunctionCode::UnsolicitedResponse,
            0x83 => Dnp3FunctionCode::AuthenticationResponse,
            _ => Dnp3FunctionCode::Read, // Default fallback
        }
    }
}

impl Dnp3InternalIndications {
    /// Parse internal indications from two bytes
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        let iin1 = bytes[0];
        let iin2 = bytes[1];

        Self {
            broadcast: (iin1 & 0x01) != 0,
            class_1_events: (iin1 & 0x02) != 0,
            class_2_events: (iin1 & 0x04) != 0,
            class_3_events: (iin1 & 0x08) != 0,
            need_time: (iin1 & 0x10) != 0,
            local_control: (iin1 & 0x20) != 0,
            device_trouble: (iin1 & 0x40) != 0,
            device_restart: (iin1 & 0x80) != 0,
            no_func_code_support: (iin2 & 0x01) != 0,
            object_unknown: (iin2 & 0x02) != 0,
            parameter_error: (iin2 & 0x04) != 0,
            event_buffer_overflow: (iin2 & 0x08) != 0,
            already_executing: (iin2 & 0x10) != 0,
            config_corrupt: (iin2 & 0x20) != 0,
            reserved_2: (iin2 & 0x40) != 0,
            reserved_1: (iin2 & 0x80) != 0,
        }
    }
}

/// Parse DNP3 application layer message
pub fn parse_dnp3_application_layer(data: &[u8]) -> Result<Dnp3ApplicationMessage, Dnp3ParseError> {
    if data.len() < 2 {
        return Err(Dnp3ParseError::InsufficientData);
    }

    let application_control = data[0];
    let function_code = Dnp3FunctionCode::from(data[1]);

    let mut offset = 2;
    let mut internal_indications = None;

    // Check if this is a response message (has internal indications)
    if matches!(
        function_code,
        Dnp3FunctionCode::Response | Dnp3FunctionCode::UnsolicitedResponse
    ) {
        if data.len() < offset + 2 {
            return Err(Dnp3ParseError::InsufficientData);
        }
        internal_indications = Some(Dnp3InternalIndications::from_bytes([
            data[offset],
            data[offset + 1],
        ]));
        offset += 2;
    }

    let header = Dnp3ApplicationHeader {
        application_control,
        function_code,
        internal_indications,
    };

    let mut objects = Vec::new();
    let mut remaining_data = Vec::new();

    // Parse object headers
    while offset < data.len() {
        if offset + 3 > data.len() {
            // Remaining data is payload
            remaining_data.extend_from_slice(&data[offset..]);
            break;
        }

        let group = data[offset];
        let variation = data[offset + 1];
        let qualifier = data[offset + 2];
        offset += 3;

        // Parse range field based on qualifier
        match parse_range_field(&data[offset..], qualifier) {
            Ok(range_field) => {
                offset += range_field.len();
                objects.push(Dnp3ObjectHeader {
                    group,
                    variation,
                    qualifier,
                    range_field,
                });
            }
            Err(_) => {
                // If range field parsing fails, treat remaining data as payload
                remaining_data.extend_from_slice(&data[offset - 3..]);
                break;
            }
        }

        // If this is a data object, the rest might be data
        if group == 0 && variation == 0 {
            break;
        }
    }

    // Collect remaining data
    if offset < data.len() {
        remaining_data.extend_from_slice(&data[offset..]);
    }

    Ok(Dnp3ApplicationMessage {
        header,
        objects,
        data: remaining_data,
    })
}

/// Parse range field based on qualifier code
fn parse_range_field(data: &[u8], qualifier: u8) -> Result<Vec<u8>, Dnp3ParseError> {
    let range_type = qualifier & 0x0F;

    match range_type {
        0x00 => Ok(vec![]), // No range field
        0x01 => {
            // 1-byte start and stop indices
            if data.len() < 2 {
                return Err(Dnp3ParseError::InsufficientData);
            }
            Ok(data[0..2].to_vec())
        }
        0x02 => {
            // 2-byte start and stop indices
            if data.len() < 4 {
                return Err(Dnp3ParseError::InsufficientData);
            }
            Ok(data[0..4].to_vec())
        }
        0x03 => {
            // 4-byte start and stop indices
            if data.len() < 8 {
                return Err(Dnp3ParseError::InsufficientData);
            }
            Ok(data[0..8].to_vec())
        }
        0x04 => {
            // 1-byte start index and 1-byte quantity
            if data.len() < 2 {
                return Err(Dnp3ParseError::InsufficientData);
            }
            Ok(data[0..2].to_vec())
        }
        0x05 => {
            // 2-byte start index and 1-byte quantity
            if data.len() < 3 {
                return Err(Dnp3ParseError::InsufficientData);
            }
            Ok(data[0..3].to_vec())
        }
        0x06 => {
            // 4-byte start index and 2-byte quantity
            if data.len() < 6 {
                return Err(Dnp3ParseError::InsufficientData);
            }
            Ok(data[0..6].to_vec())
        }
        0x07 | 0x08 => {
            // 1-byte or 2-byte quantity of objects
            let len = if range_type == 0x07 { 1 } else { 2 };
            if data.len() < len {
                return Err(Dnp3ParseError::InsufficientData);
            }
            Ok(data[0..len].to_vec())
        }
        _ => Err(Dnp3ParseError::InvalidQualifier(qualifier)),
    }
}

/// Extract specific object data from DNP3 message
pub fn extract_object_data(message: &Dnp3ApplicationMessage, group: u8, variation: u8) -> Vec<u8> {
    for obj in &message.objects {
        if obj.group == group && obj.variation == variation {
            return message.data.clone();
        }
    }
    Vec::new()
}

/// Check if DNP3 message is a response
pub fn is_response_message(message: &Dnp3ApplicationMessage) -> bool {
    matches!(
        message.header.function_code,
        Dnp3FunctionCode::Response
            | Dnp3FunctionCode::UnsolicitedResponse
            | Dnp3FunctionCode::AuthenticationResponse
    )
}

/// Get human-readable function code description
pub fn get_function_code_description(func_code: Dnp3FunctionCode) -> &'static str {
    match func_code {
        Dnp3FunctionCode::Confirm => "Confirm",
        Dnp3FunctionCode::Read => "Read",
        Dnp3FunctionCode::Write => "Write",
        Dnp3FunctionCode::Select => "Select",
        Dnp3FunctionCode::Operate => "Operate",
        Dnp3FunctionCode::DirectOperate => "Direct Operate",
        Dnp3FunctionCode::DirectOperateNoAck => "Direct Operate No Ack",
        Dnp3FunctionCode::ImmediateFreeze => "Immediate Freeze",
        Dnp3FunctionCode::ImmediateFreezeNoAck => "Immediate Freeze No Ack",
        Dnp3FunctionCode::FreezeClear => "Freeze Clear",
        Dnp3FunctionCode::FreezeClearNoAck => "Freeze Clear No Ack",
        Dnp3FunctionCode::FreezeAtTime => "Freeze At Time",
        Dnp3FunctionCode::FreezeAtTimeNoAck => "Freeze At Time No Ack",
        Dnp3FunctionCode::ColdRestart => "Cold Restart",
        Dnp3FunctionCode::WarmRestart => "Warm Restart",
        Dnp3FunctionCode::InitializeData => "Initialize Data",
        Dnp3FunctionCode::InitializeApplication => "Initialize Application",
        Dnp3FunctionCode::StartApplication => "Start Application",
        Dnp3FunctionCode::StopApplication => "Stop Application",
        Dnp3FunctionCode::SaveConfiguration => "Save Configuration",
        Dnp3FunctionCode::EnableUnsolicited => "Enable Unsolicited",
        Dnp3FunctionCode::DisableUnsolicited => "Disable Unsolicited",
        Dnp3FunctionCode::AssignClass => "Assign Class",
        Dnp3FunctionCode::DelayMeasure => "Delay Measure",
        Dnp3FunctionCode::RecordCurrentTime => "Record Current Time",
        Dnp3FunctionCode::OpenFile => "Open File",
        Dnp3FunctionCode::CloseFile => "Close File",
        Dnp3FunctionCode::DeleteFile => "Delete File",
        Dnp3FunctionCode::GetFileInfo => "Get File Info",
        Dnp3FunctionCode::AuthenticateFile => "Authenticate File",
        Dnp3FunctionCode::AbortFile => "Abort File",
        Dnp3FunctionCode::Response => "Response",
        Dnp3FunctionCode::UnsolicitedResponse => "Unsolicited Response",
        Dnp3FunctionCode::AuthenticationResponse => "Authentication Response",
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_code_conversion() {
        assert_eq!(Dnp3FunctionCode::from(0x01), Dnp3FunctionCode::Read);
        assert_eq!(Dnp3FunctionCode::from(0x02), Dnp3FunctionCode::Write);
        assert_eq!(Dnp3FunctionCode::from(0x81), Dnp3FunctionCode::Response);
        assert_eq!(
            Dnp3FunctionCode::from(0x82),
            Dnp3FunctionCode::UnsolicitedResponse
        );
    }

    #[test]
    fn test_internal_indications_parsing() {
        let iin_bytes = [0xFF, 0xFF]; // All flags set
        let iin = Dnp3InternalIndications::from_bytes(iin_bytes);

        assert!(iin.broadcast);
        assert!(iin.class_1_events);
        assert!(iin.class_2_events);
        assert!(iin.class_3_events);
        assert!(iin.need_time);
        assert!(iin.local_control);
        assert!(iin.device_trouble);
        assert!(iin.device_restart);
        assert!(iin.no_func_code_support);
        assert!(iin.object_unknown);
        assert!(iin.parameter_error);
        assert!(iin.event_buffer_overflow);
        assert!(iin.already_executing);
        assert!(iin.config_corrupt);
        assert!(iin.reserved_2);
        assert!(iin.reserved_1);
    }

    #[test]
    fn test_internal_indications_partial() {
        let iin_bytes = [0x01, 0x02]; // Only broadcast and object_unknown set
        let iin = Dnp3InternalIndications::from_bytes(iin_bytes);

        assert!(iin.broadcast);
        assert!(!iin.class_1_events);
        assert!(!iin.class_2_events);
        assert!(!iin.class_3_events);
        assert!(!iin.need_time);
        assert!(!iin.local_control);
        assert!(!iin.device_trouble);
        assert!(!iin.device_restart);
        assert!(!iin.no_func_code_support);
        assert!(iin.object_unknown);
        assert!(!iin.parameter_error);
    }

    #[test]
    fn test_parse_simple_read_request() {
        // Simple read request: AC=0xC0, FC=0x01 (Read)
        let data = vec![0xC0, 0x01];

        let result = parse_dnp3_application_layer(&data);
        assert!(result.is_ok());

        let message = result.unwrap();
        assert_eq!(message.header.application_control, 0xC0);
        assert_eq!(message.header.function_code, Dnp3FunctionCode::Read);
        assert!(message.header.internal_indications.is_none());
        assert!(message.objects.is_empty());
        assert!(message.data.is_empty());
    }

    #[test]
    fn test_parse_response_with_iin() {
        // Response with internal indications: AC=0xC0, FC=0x81 (Response), IIN=0x00,0x00
        let data = vec![0xC0, 0x81, 0x00, 0x00];

        let result = parse_dnp3_application_layer(&data);
        assert!(result.is_ok());

        let message = result.unwrap();
        assert_eq!(message.header.application_control, 0xC0);
        assert_eq!(message.header.function_code, Dnp3FunctionCode::Response);
        assert!(message.header.internal_indications.is_some());

        let iin = message.header.internal_indications.unwrap();
        assert!(!iin.broadcast);
        assert!(!iin.class_1_events);
        assert!(!iin.device_trouble);
    }

    #[test]
    fn test_parse_read_request_with_object() {
        // Read request with object header: AC=0xC0, FC=0x01, Group=1, Var=2, Qual=0x00 (no range)
        let data = vec![0xC0, 0x01, 0x01, 0x02, 0x00];

        let result = parse_dnp3_application_layer(&data);
        assert!(result.is_ok());

        let message = result.unwrap();
        assert_eq!(message.header.function_code, Dnp3FunctionCode::Read);
        assert_eq!(message.objects.len(), 1);

        let obj = &message.objects[0];
        assert_eq!(obj.group, 1);
        assert_eq!(obj.variation, 2);
        assert_eq!(obj.qualifier, 0x00);
    }

    #[test]
    fn test_parse_insufficient_data() {
        let data = vec![0xC0]; // Only one byte

        let result = parse_dnp3_application_layer(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Dnp3ParseError::InsufficientData);
    }

    #[test]
    fn test_parse_response_insufficient_iin_data() {
        let data = vec![0xC0, 0x81, 0x00]; // Response but missing second IIN byte

        let result = parse_dnp3_application_layer(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Dnp3ParseError::InsufficientData);
    }

    #[test]
    fn test_range_field_parsing_no_range() {
        let data = vec![];
        let result = parse_range_field(&data, 0x00);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_range_field_parsing_1byte_indices() {
        let data = vec![0x10, 0x20, 0x30, 0x40];
        let result = parse_range_field(&data, 0x01);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x10, 0x20]);
    }

    #[test]
    fn test_range_field_parsing_2byte_indices() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let result = parse_range_field(&data, 0x02);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x10, 0x20, 0x30, 0x40]);
    }

    #[test]
    fn test_range_field_parsing_insufficient_data() {
        let data = vec![0x10];
        let result = parse_range_field(&data, 0x01); // Needs 2 bytes
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Dnp3ParseError::InsufficientData);
    }

    #[test]
    fn test_range_field_parsing_invalid_qualifier() {
        let data = vec![0x10, 0x20];
        let result = parse_range_field(&data, 0xFF); // Invalid qualifier
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Dnp3ParseError::InvalidQualifier(0xFF));
    }

    #[test]
    fn test_extract_object_data() {
        let message = Dnp3ApplicationMessage {
            header: Dnp3ApplicationHeader {
                application_control: 0xC0,
                function_code: Dnp3FunctionCode::Response,
                internal_indications: None,
            },
            objects: vec![
                Dnp3ObjectHeader {
                    group: 1,
                    variation: 2,
                    qualifier: 0x06,
                    range_field: vec![],
                },
                Dnp3ObjectHeader {
                    group: 2,
                    variation: 1,
                    qualifier: 0x06,
                    range_field: vec![],
                },
            ],
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };

        let data = extract_object_data(&message, 1, 2);
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC, 0xDD]);

        let no_data = extract_object_data(&message, 3, 4);
        assert!(no_data.is_empty());
    }

    #[test]
    fn test_is_response_message() {
        let request_message = Dnp3ApplicationMessage {
            header: Dnp3ApplicationHeader {
                application_control: 0xC0,
                function_code: Dnp3FunctionCode::Read,
                internal_indications: None,
            },
            objects: vec![],
            data: vec![],
        };

        let response_message = Dnp3ApplicationMessage {
            header: Dnp3ApplicationHeader {
                application_control: 0xC0,
                function_code: Dnp3FunctionCode::Response,
                internal_indications: None,
            },
            objects: vec![],
            data: vec![],
        };

        let unsolicited_message = Dnp3ApplicationMessage {
            header: Dnp3ApplicationHeader {
                application_control: 0xC0,
                function_code: Dnp3FunctionCode::UnsolicitedResponse,
                internal_indications: None,
            },
            objects: vec![],
            data: vec![],
        };

        assert!(!is_response_message(&request_message));
        assert!(is_response_message(&response_message));
        assert!(is_response_message(&unsolicited_message));
    }

    #[test]
    fn test_get_function_code_description() {
        assert_eq!(
            get_function_code_description(Dnp3FunctionCode::Read),
            "Read"
        );
        assert_eq!(
            get_function_code_description(Dnp3FunctionCode::Write),
            "Write"
        );
        assert_eq!(
            get_function_code_description(Dnp3FunctionCode::Response),
            "Response"
        );
        assert_eq!(
            get_function_code_description(Dnp3FunctionCode::ColdRestart),
            "Cold Restart"
        );
        assert_eq!(
            get_function_code_description(Dnp3FunctionCode::UnsolicitedResponse),
            "Unsolicited Response"
        );
    }

    #[test]
    fn test_complex_message_parsing() {
        // Complex message: Response with IIN and object data
        let data = vec![
            0xC0, 0x81, // AC, FC (Response)
            0x10, 0x04, // IIN (need_time=true, parameter_error=true)
            0x01, 0x02, 0x00, // Object: Group=1, Var=2, Qual=0x00 (no range)
            0xAA, 0xBB, 0xCC, // Data payload
        ];

        let result = parse_dnp3_application_layer(&data);
        assert!(result.is_ok());

        let message = result.unwrap();
        assert_eq!(message.header.function_code, Dnp3FunctionCode::Response);

        let iin = message.header.internal_indications.unwrap();
        assert!(iin.need_time);
        assert!(iin.parameter_error);
        assert!(!iin.broadcast);

        assert_eq!(message.objects.len(), 1);
        assert_eq!(message.objects[0].group, 1);
        assert_eq!(message.objects[0].variation, 2);
        assert_eq!(message.objects[0].qualifier, 0x00);

        assert_eq!(message.data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_multiple_objects_parsing() {
        // Message with multiple object headers
        let data = vec![
            0xC0, 0x01, // AC, FC (Read)
            0x01, 0x02, 0x00, // Object 1: Group=1, Var=2, Qual=0x00
            0x02, 0x01, 0x00, // Object 2: Group=2, Var=1, Qual=0x00
            0x03, 0x04, 0x00, // Object 3: Group=3, Var=4, Qual=0x00
        ];

        let result = parse_dnp3_application_layer(&data);
        assert!(result.is_ok());

        let message = result.unwrap();
        assert_eq!(message.objects.len(), 3);

        assert_eq!(message.objects[0].group, 1);
        assert_eq!(message.objects[0].variation, 2);

        assert_eq!(message.objects[1].group, 2);
        assert_eq!(message.objects[1].variation, 1);

        assert_eq!(message.objects[2].group, 3);
        assert_eq!(message.objects[2].variation, 4);
    }

    #[test]
    fn test_range_field_1byte_quantity() {
        let data = vec![0x05, 0x10, 0x20]; // 5 objects starting from some point
        let result = parse_range_field(&data, 0x07);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x05]);
    }

    #[test]
    fn test_range_field_2byte_quantity() {
        let data = vec![0x00, 0x10, 0x20, 0x30]; // 16 objects (0x0010)
        let result = parse_range_field(&data, 0x08);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x00, 0x10]);
    }
}
