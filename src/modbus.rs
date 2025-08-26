use std::fmt;

/// Modbus TCP Application Data Unit (ADU) structure
#[derive(Debug, Clone, PartialEq)]
pub struct ModbusTcpAdu {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub data: Vec<u8>,
}

/// Modbus function codes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FunctionCode {
    ReadCoils = 0x01,
    ReadDiscreteInputs = 0x02,
    ReadHoldingRegisters = 0x03,
    ReadInputRegisters = 0x04,
    WriteSingleCoil = 0x05,
    WriteSingleRegister = 0x06,
    WriteMultipleCoils = 0x0F,
    WriteMultipleRegisters = 0x10,
}

impl TryFrom<u8> for FunctionCode {
    type Error = ModbusError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0x01 => Ok(FunctionCode::ReadCoils),
            0x02 => Ok(FunctionCode::ReadDiscreteInputs),
            0x03 => Ok(FunctionCode::ReadHoldingRegisters),
            0x04 => Ok(FunctionCode::ReadInputRegisters),
            0x05 => Ok(FunctionCode::WriteSingleCoil),
            0x06 => Ok(FunctionCode::WriteSingleRegister),
            0x0F => Ok(FunctionCode::WriteMultipleCoils),
            0x10 => Ok(FunctionCode::WriteMultipleRegisters),
            _ => Err(ModbusError::InvalidFunctionCode),
        }
    }
}

/// Modbus parsing errors
#[derive(Debug, PartialEq)]
pub enum ModbusError {
    InvalidLength,
    InvalidProtocolId,
    BufferTooShort,
    InvalidFunctionCode,
}

impl fmt::Display for ModbusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModbusError::InvalidLength => write!(f, "Invalid length field"),
            ModbusError::InvalidProtocolId => write!(f, "Invalid protocol ID (must be 0)"),
            ModbusError::BufferTooShort => write!(f, "Buffer too short for Modbus TCP frame"),
            ModbusError::InvalidFunctionCode => write!(f, "Invalid function code"),
        }
    }
}

impl std::error::Error for ModbusError {}

/// Parse Modbus TCP ADU from byte buffer
pub fn parse_modbus_tcp_adu(buffer: &[u8]) -> Result<ModbusTcpAdu, ModbusError> {
    // Minimum Modbus TCP frame is 8 bytes (MBAP header + function code)
    if buffer.len() < 8 {
        return Err(ModbusError::BufferTooShort);
    }

    // Parse MBAP (Modbus Application Protocol) header
    let transaction_id = u16::from_be_bytes([buffer[0], buffer[1]]);
    let protocol_id = u16::from_be_bytes([buffer[2], buffer[3]]);
    let length = u16::from_be_bytes([buffer[4], buffer[5]]);
    let unit_id = buffer[6];
    let function_code = buffer[7];

    // Validate protocol ID (must be 0 for Modbus)
    if protocol_id != 0 {
        return Err(ModbusError::InvalidProtocolId);
    }

    // Validate length field
    let expected_length = buffer.len() - 6; // Total length minus transaction_id and protocol_id
    if length as usize != expected_length {
        return Err(ModbusError::InvalidLength);
    }

    // Extract data portion (everything after function code)
    let data = if buffer.len() > 8 {
        buffer[8..].to_vec()
    } else {
        Vec::new()
    };

    Ok(ModbusTcpAdu {
        transaction_id,
        protocol_id,
        length,
        unit_id,
        function_code,
        data,
    })
}

/// Create Modbus TCP ADU byte representation
pub fn create_modbus_tcp_adu(
    transaction_id: u16,
    unit_id: u8,
    function_code: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut buffer = Vec::new();

    // MBAP header
    buffer.extend_from_slice(&transaction_id.to_be_bytes());
    buffer.extend_from_slice(&0u16.to_be_bytes()); // Protocol ID (always 0)

    let length = 2 + data.len() as u16; // Unit ID + Function Code + Data
    buffer.extend_from_slice(&length.to_be_bytes());

    buffer.push(unit_id);
    buffer.push(function_code);
    buffer.extend_from_slice(data);

    buffer
}

/// Parse Read Holding Registers request
pub fn parse_read_holding_registers_request(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);

    Ok((starting_address, quantity))
}

/// Parse Read Holding Registers response
pub fn parse_read_holding_registers_response(data: &[u8]) -> Result<Vec<u16>, ModbusError> {
    if data.is_empty() {
        return Err(ModbusError::InvalidLength);
    }

    let byte_count = data[0] as usize;

    if data.len() != byte_count + 1 || byte_count % 2 != 0 {
        return Err(ModbusError::InvalidLength);
    }

    let mut registers = Vec::new();
    for i in (1..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let register = u16::from_be_bytes([data[i], data[i + 1]]);
            registers.push(register);
        }
    }

    Ok(registers)
}

/// Parse Read Coils request (Function Code 0x01)
pub fn parse_read_coils_request(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);

    Ok((starting_address, quantity))
}

/// Parse Read Coils response (Function Code 0x01)
pub fn parse_read_coils_response(data: &[u8]) -> Result<Vec<bool>, ModbusError> {
    if data.is_empty() {
        return Err(ModbusError::InvalidLength);
    }

    let byte_count = data[0] as usize;

    if data.len() != byte_count + 1 {
        return Err(ModbusError::InvalidLength);
    }

    let mut coils = Vec::new();
    for i in 1..=byte_count {
        let byte_val = data[i];
        for bit in 0..8 {
            coils.push((byte_val & (1 << bit)) != 0);
        }
    }

    Ok(coils)
}

/// Parse Read Discrete Inputs request (Function Code 0x02)
pub fn parse_read_discrete_inputs_request(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);

    Ok((starting_address, quantity))
}

/// Parse Read Discrete Inputs response (Function Code 0x02)
pub fn parse_read_discrete_inputs_response(data: &[u8]) -> Result<Vec<bool>, ModbusError> {
    if data.is_empty() {
        return Err(ModbusError::InvalidLength);
    }

    let byte_count = data[0] as usize;

    if data.len() != byte_count + 1 {
        return Err(ModbusError::InvalidLength);
    }

    let mut inputs = Vec::new();
    for i in 1..=byte_count {
        let byte_val = data[i];
        for bit in 0..8 {
            inputs.push((byte_val & (1 << bit)) != 0);
        }
    }

    Ok(inputs)
}

/// Parse Read Input Registers request (Function Code 0x04)
pub fn parse_read_input_registers_request(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);

    Ok((starting_address, quantity))
}

/// Parse Read Input Registers response (Function Code 0x04)
pub fn parse_read_input_registers_response(data: &[u8]) -> Result<Vec<u16>, ModbusError> {
    if data.is_empty() {
        return Err(ModbusError::InvalidLength);
    }

    let byte_count = data[0] as usize;

    if data.len() != byte_count + 1 || byte_count % 2 != 0 {
        return Err(ModbusError::InvalidLength);
    }

    let mut registers = Vec::new();
    for i in (1..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let register = u16::from_be_bytes([data[i], data[i + 1]]);
            registers.push(register);
        }
    }

    Ok(registers)
}

/// Parse Write Single Coil request (Function Code 0x05)
pub fn parse_write_single_coil_request(data: &[u8]) -> Result<(u16, bool), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let address = u16::from_be_bytes([data[0], data[1]]);
    let value = u16::from_be_bytes([data[2], data[3]]);

    // Modbus standard: 0xFF00 = ON, 0x0000 = OFF
    let coil_value = match value {
        0xFF00 => true,
        0x0000 => false,
        _ => return Err(ModbusError::InvalidLength),
    };

    Ok((address, coil_value))
}

/// Parse Write Single Coil response (Function Code 0x05)
pub fn parse_write_single_coil_response(data: &[u8]) -> Result<(u16, bool), ModbusError> {
    parse_write_single_coil_request(data) // Same format as request
}

/// Parse Write Single Register request (Function Code 0x06)
pub fn parse_write_single_register_request(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let address = u16::from_be_bytes([data[0], data[1]]);
    let value = u16::from_be_bytes([data[2], data[3]]);

    Ok((address, value))
}

/// Parse Write Single Register response (Function Code 0x06)
pub fn parse_write_single_register_response(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    parse_write_single_register_request(data) // Same format as request
}

/// Parse Write Multiple Coils request (Function Code 0x0F)
pub fn parse_write_multiple_coils_request(
    data: &[u8],
) -> Result<(u16, u16, Vec<bool>), ModbusError> {
    if data.len() < 5 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);
    let byte_count = data[4] as usize;

    if data.len() != 5 + byte_count {
        return Err(ModbusError::InvalidLength);
    }

    let mut coils = Vec::new();
    for i in 0..byte_count {
        let byte_val = data[5 + i];
        for bit in 0..8 {
            if coils.len() < quantity as usize {
                coils.push((byte_val & (1 << bit)) != 0);
            }
        }
    }

    Ok((starting_address, quantity, coils))
}

/// Parse Write Multiple Coils response (Function Code 0x0F)
pub fn parse_write_multiple_coils_response(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);

    Ok((starting_address, quantity))
}

/// Parse Write Multiple Registers request (Function Code 0x10)
pub fn parse_write_multiple_registers_request(
    data: &[u8],
) -> Result<(u16, u16, Vec<u16>), ModbusError> {
    if data.len() < 5 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);
    let byte_count = data[4] as usize;

    if data.len() != 5 + byte_count || byte_count % 2 != 0 {
        return Err(ModbusError::InvalidLength);
    }

    let mut registers = Vec::new();
    for i in (5..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let register = u16::from_be_bytes([data[i], data[i + 1]]);
            registers.push(register);
        }
    }

    Ok((starting_address, quantity, registers))
}

/// Parse Write Multiple Registers response (Function Code 0x10)
pub fn parse_write_multiple_registers_response(data: &[u8]) -> Result<(u16, u16), ModbusError> {
    if data.len() != 4 {
        return Err(ModbusError::InvalidLength);
    }

    let starting_address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);

    Ok((starting_address, quantity))
}

/// Create Read Coils request data
pub fn create_read_coils_request(starting_address: u16, quantity: u16) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&starting_address.to_be_bytes());
    data.extend_from_slice(&quantity.to_be_bytes());
    data
}

/// Create Read Coils response data
pub fn create_read_coils_response(coils: &[bool]) -> Vec<u8> {
    let byte_count = (coils.len() + 7) / 8; // Round up to nearest byte
    let mut data = Vec::new();
    data.push(byte_count as u8);

    for chunk in coils.chunks(8) {
        let mut byte_val = 0u8;
        for (i, &coil) in chunk.iter().enumerate() {
            if coil {
                byte_val |= 1 << i;
            }
        }
        data.push(byte_val);
    }

    data
}

/// Create Write Single Coil request data
pub fn create_write_single_coil_request(address: u16, value: bool) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&address.to_be_bytes());
    let coil_value = if value { 0xFF00u16 } else { 0x0000u16 };
    data.extend_from_slice(&coil_value.to_be_bytes());
    data
}

/// Create Write Single Register request data
pub fn create_write_single_register_request(address: u16, value: u16) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&address.to_be_bytes());
    data.extend_from_slice(&value.to_be_bytes());
    data
}

/// Create Write Multiple Coils request data
pub fn create_write_multiple_coils_request(starting_address: u16, coils: &[bool]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&starting_address.to_be_bytes());
    data.extend_from_slice(&(coils.len() as u16).to_be_bytes());

    let byte_count = (coils.len() + 7) / 8;
    data.push(byte_count as u8);

    for chunk in coils.chunks(8) {
        let mut byte_val = 0u8;
        for (i, &coil) in chunk.iter().enumerate() {
            if coil {
                byte_val |= 1 << i;
            }
        }
        data.push(byte_val);
    }

    data
}

/// Create Write Multiple Registers request data
pub fn create_write_multiple_registers_request(
    starting_address: u16,
    registers: &[u16],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&starting_address.to_be_bytes());
    data.extend_from_slice(&(registers.len() as u16).to_be_bytes());
    data.push((registers.len() * 2) as u8); // Byte count

    for &register in registers {
        data.extend_from_slice(&register.to_be_bytes());
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_modbus_tcp_adu() {
        // Valid Modbus TCP frame: Read Holding Registers
        let buffer = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID
            0x00, 0x06, // Length
            0x01, // Unit ID
            0x03, // Function Code (Read Holding Registers)
            0x00, 0x00, // Starting Address
            0x00, 0x02, // Quantity
        ];

        let result = parse_modbus_tcp_adu(&buffer);
        assert!(result.is_ok());

        let adu = result.unwrap();
        assert_eq!(adu.transaction_id, 1);
        assert_eq!(adu.protocol_id, 0);
        assert_eq!(adu.length, 6);
        assert_eq!(adu.unit_id, 1);
        assert_eq!(adu.function_code, 3);
        assert_eq!(adu.data, vec![0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_parse_buffer_too_short() {
        let buffer = vec![0x00, 0x01, 0x00]; // Too short
        let result = parse_modbus_tcp_adu(&buffer);
        assert_eq!(result, Err(ModbusError::BufferTooShort));
    }

    #[test]
    fn test_parse_invalid_protocol_id() {
        let buffer = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x01, // Invalid Protocol ID (should be 0)
            0x00, 0x02, // Length
            0x01, // Unit ID
            0x03, // Function Code
        ];

        let result = parse_modbus_tcp_adu(&buffer);
        assert_eq!(result, Err(ModbusError::InvalidProtocolId));
    }

    #[test]
    fn test_parse_invalid_length() {
        let buffer = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID
            0x00, 0x10, // Invalid Length (too large)
            0x01, // Unit ID
            0x03, // Function Code
        ];

        let result = parse_modbus_tcp_adu(&buffer);
        assert_eq!(result, Err(ModbusError::InvalidLength));
    }

    #[test]
    fn test_create_modbus_tcp_adu() {
        let data = vec![0x00, 0x00, 0x00, 0x02];
        let buffer = create_modbus_tcp_adu(1, 1, 3, &data);

        let expected = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID
            0x00, 0x06, // Length
            0x01, // Unit ID
            0x03, // Function Code
            0x00, 0x00, 0x00, 0x02, // Data
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_function_code_conversion() {
        assert_eq!(
            FunctionCode::try_from(0x01).unwrap(),
            FunctionCode::ReadCoils
        );
        assert_eq!(
            FunctionCode::try_from(0x03).unwrap(),
            FunctionCode::ReadHoldingRegisters
        );
        assert_eq!(
            FunctionCode::try_from(0xFF),
            Err(ModbusError::InvalidFunctionCode)
        );
    }

    #[test]
    fn test_parse_read_holding_registers_request() {
        let data = vec![0x00, 0x00, 0x00, 0x02]; // Start: 0, Quantity: 2
        let result = parse_read_holding_registers_request(&data);
        assert!(result.is_ok());

        let (start, quantity) = result.unwrap();
        assert_eq!(start, 0);
        assert_eq!(quantity, 2);
    }

    #[test]
    fn test_parse_read_holding_registers_response() {
        let data = vec![0x04, 0x00, 0x0A, 0x00, 0x14]; // 2 registers: 10, 20
        let result = parse_read_holding_registers_response(&data);
        assert!(result.is_ok());

        let registers = result.unwrap();
        assert_eq!(registers, vec![10, 20]);
    }

    #[test]
    fn test_complete_modbus_transaction() {
        // Create a request
        let request_data = vec![0x00, 0x00, 0x00, 0x02]; // Read 2 registers from address 0
        let request_frame = create_modbus_tcp_adu(1, 1, 3, &request_data);

        // Parse the request
        let parsed_request = parse_modbus_tcp_adu(&request_frame).unwrap();
        assert_eq!(parsed_request.function_code, 3);
        assert_eq!(parsed_request.transaction_id, 1);

        // Parse request data
        let (start_addr, quantity) =
            parse_read_holding_registers_request(&parsed_request.data).unwrap();
        assert_eq!(start_addr, 0);
        assert_eq!(quantity, 2);

        // Create a response
        let response_data = vec![0x04, 0x00, 0x0A, 0x00, 0x14]; // 2 registers: 10, 20
        let response_frame = create_modbus_tcp_adu(1, 1, 3, &response_data);

        // Parse the response
        let parsed_response = parse_modbus_tcp_adu(&response_frame).unwrap();
        let registers = parse_read_holding_registers_response(&parsed_response.data).unwrap();
        assert_eq!(registers, vec![10, 20]);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", ModbusError::InvalidLength),
            "Invalid length field"
        );
        assert_eq!(
            format!("{}", ModbusError::BufferTooShort),
            "Buffer too short for Modbus TCP frame"
        );
    }

    // Read Coils tests
    #[test]
    fn test_parse_read_coils_request() {
        let data = vec![0x00, 0x13, 0x00, 0x25]; // Start: 19, Quantity: 37
        let result = parse_read_coils_request(&data);
        assert!(result.is_ok());

        let (start, quantity) = result.unwrap();
        assert_eq!(start, 19);
        assert_eq!(quantity, 37);
    }

    #[test]
    fn test_parse_read_coils_response() {
        let data = vec![0x03, 0xCD, 0x6B, 0x05]; // 3 bytes of coil data
        let result = parse_read_coils_response(&data);
        assert!(result.is_ok());

        let coils = result.unwrap();
        assert_eq!(coils.len(), 24); // 3 bytes * 8 bits
        // Test some specific bits based on 0xCD = 11001101
        assert!(coils[0]); // bit 0
        assert!(!coils[1]); // bit 1
        assert!(coils[2]); // bit 2
        assert!(coils[3]); // bit 3
    }

    #[test]
    fn test_create_read_coils_request() {
        let data = create_read_coils_request(19, 37);
        assert_eq!(data, vec![0x00, 0x13, 0x00, 0x25]);
    }

    #[test]
    fn test_create_read_coils_response() {
        let coils = vec![true, false, true, true, false, false, true, true]; // 0xCD
        let data = create_read_coils_response(&coils);
        assert_eq!(data, vec![0x01, 0xCD]);
    }

    // Read Discrete Inputs tests
    #[test]
    fn test_parse_read_discrete_inputs_request() {
        let data = vec![0x00, 0xC4, 0x00, 0x16]; // Start: 196, Quantity: 22
        let result = parse_read_discrete_inputs_request(&data);
        assert!(result.is_ok());

        let (start, quantity) = result.unwrap();
        assert_eq!(start, 196);
        assert_eq!(quantity, 22);
    }

    #[test]
    fn test_parse_read_discrete_inputs_response() {
        let data = vec![0x03, 0xAC, 0xDB, 0x35]; // 3 bytes of input data
        let result = parse_read_discrete_inputs_response(&data);
        assert!(result.is_ok());

        let inputs = result.unwrap();
        assert_eq!(inputs.len(), 24);
    }

    // Read Input Registers tests
    #[test]
    fn test_parse_read_input_registers_request() {
        let data = vec![0x00, 0x08, 0x00, 0x01]; // Start: 8, Quantity: 1
        let result = parse_read_input_registers_request(&data);
        assert!(result.is_ok());

        let (start, quantity) = result.unwrap();
        assert_eq!(start, 8);
        assert_eq!(quantity, 1);
    }

    #[test]
    fn test_parse_read_input_registers_response() {
        let data = vec![0x02, 0x00, 0x0A]; // 1 register: 10
        let result = parse_read_input_registers_response(&data);
        assert!(result.is_ok());

        let registers = result.unwrap();
        assert_eq!(registers, vec![10]);
    }

    // Write Single Coil tests
    #[test]
    fn test_parse_write_single_coil_request() {
        let data = vec![0x00, 0xAC, 0xFF, 0x00]; // Address: 172, Value: ON
        let result = parse_write_single_coil_request(&data);
        assert!(result.is_ok());

        let (address, value) = result.unwrap();
        assert_eq!(address, 172);
        assert_eq!(value, true);
    }

    #[test]
    fn test_parse_write_single_coil_request_off() {
        let data = vec![0x00, 0xAC, 0x00, 0x00]; // Address: 172, Value: OFF
        let result = parse_write_single_coil_request(&data);
        assert!(result.is_ok());

        let (address, value) = result.unwrap();
        assert_eq!(address, 172);
        assert_eq!(value, false);
    }

    #[test]
    fn test_create_write_single_coil_request() {
        let data = create_write_single_coil_request(172, true);
        assert_eq!(data, vec![0x00, 0xAC, 0xFF, 0x00]);

        let data = create_write_single_coil_request(172, false);
        assert_eq!(data, vec![0x00, 0xAC, 0x00, 0x00]);
    }

    // Write Single Register tests
    #[test]
    fn test_parse_write_single_register_request() {
        let data = vec![0x00, 0x01, 0x00, 0x03]; // Address: 1, Value: 3
        let result = parse_write_single_register_request(&data);
        assert!(result.is_ok());

        let (address, value) = result.unwrap();
        assert_eq!(address, 1);
        assert_eq!(value, 3);
    }

    #[test]
    fn test_create_write_single_register_request() {
        let data = create_write_single_register_request(1, 3);
        assert_eq!(data, vec![0x00, 0x01, 0x00, 0x03]);
    }

    // Write Multiple Coils tests
    #[test]
    fn test_parse_write_multiple_coils_request() {
        let data = vec![
            0x00, 0x13, // Starting address: 19
            0x00, 0x0A, // Quantity: 10
            0x02, // Byte count: 2
            0xCD, 0x01, // Coil values
        ];
        let result = parse_write_multiple_coils_request(&data);
        assert!(result.is_ok());

        let (start, quantity, coils) = result.unwrap();
        assert_eq!(start, 19);
        assert_eq!(quantity, 10);
        assert_eq!(coils.len(), 10);
    }

    #[test]
    fn test_parse_write_multiple_coils_response() {
        let data = vec![0x00, 0x13, 0x00, 0x0A]; // Start: 19, Quantity: 10
        let result = parse_write_multiple_coils_response(&data);
        assert!(result.is_ok());

        let (start, quantity) = result.unwrap();
        assert_eq!(start, 19);
        assert_eq!(quantity, 10);
    }

    #[test]
    fn test_create_write_multiple_coils_request() {
        let coils = vec![
            true, false, true, true, false, false, true, true, true, false,
        ];
        let data = create_write_multiple_coils_request(19, &coils);

        assert_eq!(data[0..2], [0x00, 0x13]); // Starting address
        assert_eq!(data[2..4], [0x00, 0x0A]); // Quantity
        assert_eq!(data[4], 0x02); // Byte count
        // Coil data follows
    }

    // Write Multiple Registers tests
    #[test]
    fn test_parse_write_multiple_registers_request() {
        let data = vec![
            0x00, 0x01, // Starting address: 1
            0x00, 0x02, // Quantity: 2
            0x04, // Byte count: 4
            0x00, 0x0A, // Register 1: 10
            0x01, 0x02, // Register 2: 258
        ];
        let result = parse_write_multiple_registers_request(&data);
        assert!(result.is_ok());

        let (start, quantity, registers) = result.unwrap();
        assert_eq!(start, 1);
        assert_eq!(quantity, 2);
        assert_eq!(registers, vec![10, 258]);
    }

    #[test]
    fn test_parse_write_multiple_registers_response() {
        let data = vec![0x00, 0x01, 0x00, 0x02]; // Start: 1, Quantity: 2
        let result = parse_write_multiple_registers_response(&data);
        assert!(result.is_ok());

        let (start, quantity) = result.unwrap();
        assert_eq!(start, 1);
        assert_eq!(quantity, 2);
    }

    #[test]
    fn test_create_write_multiple_registers_request() {
        let registers = vec![10, 258];
        let data = create_write_multiple_registers_request(1, &registers);

        let expected = vec![
            0x00, 0x01, // Starting address: 1
            0x00, 0x02, // Quantity: 2
            0x04, // Byte count: 4
            0x00, 0x0A, // Register 1: 10
            0x01, 0x02, // Register 2: 258
        ];
        assert_eq!(data, expected);
    }

    // Complete transaction tests for different function codes
    #[test]
    fn test_complete_read_coils_transaction() {
        // Create request
        let request_data = create_read_coils_request(19, 10);
        let request_frame = create_modbus_tcp_adu(1, 1, 0x01, &request_data);

        // Parse request
        let parsed_request = parse_modbus_tcp_adu(&request_frame).unwrap();
        let (start, quantity) = parse_read_coils_request(&parsed_request.data).unwrap();
        assert_eq!(start, 19);
        assert_eq!(quantity, 10);

        // Create response
        let coils = vec![
            true, false, true, true, false, false, true, true, true, false,
        ];
        let response_data = create_read_coils_response(&coils);
        let response_frame = create_modbus_tcp_adu(1, 1, 0x01, &response_data);

        // Parse response
        let parsed_response = parse_modbus_tcp_adu(&response_frame).unwrap();
        let parsed_coils = parse_read_coils_response(&parsed_response.data).unwrap();
        assert_eq!(parsed_coils[0..10], coils);
    }

    #[test]
    fn test_complete_write_single_coil_transaction() {
        // Create request
        let request_data = create_write_single_coil_request(172, true);
        let request_frame = create_modbus_tcp_adu(1, 1, 0x05, &request_data);

        // Parse request
        let parsed_request = parse_modbus_tcp_adu(&request_frame).unwrap();
        let (address, value) = parse_write_single_coil_request(&parsed_request.data).unwrap();
        assert_eq!(address, 172);
        assert_eq!(value, true);

        // Response is same as request for write single coil
        let parsed_response = parse_modbus_tcp_adu(&request_frame).unwrap();
        let (resp_addr, resp_val) =
            parse_write_single_coil_response(&parsed_response.data).unwrap();
        assert_eq!(resp_addr, 172);
        assert_eq!(resp_val, true);
    }

    #[test]
    fn test_complete_write_multiple_registers_transaction() {
        // Create request
        let registers = vec![10, 258, 1000];
        let request_data = create_write_multiple_registers_request(1, &registers);
        let request_frame = create_modbus_tcp_adu(1, 1, 0x10, &request_data);

        // Parse request
        let parsed_request = parse_modbus_tcp_adu(&request_frame).unwrap();
        let (start, quantity, parsed_registers) =
            parse_write_multiple_registers_request(&parsed_request.data).unwrap();
        assert_eq!(start, 1);
        assert_eq!(quantity, 3);
        assert_eq!(parsed_registers, registers);

        // Create response
        let response_data = vec![0x00, 0x01, 0x00, 0x03]; // Start: 1, Quantity: 3
        let response_frame = create_modbus_tcp_adu(1, 1, 0x10, &response_data);

        // Parse response
        let parsed_response = parse_modbus_tcp_adu(&response_frame).unwrap();
        let (resp_start, resp_quantity) =
            parse_write_multiple_registers_response(&parsed_response.data).unwrap();
        assert_eq!(resp_start, 1);
        assert_eq!(resp_quantity, 3);
    }
}
