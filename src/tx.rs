use crate::serialize::write_var_int;
use crate::script::Script;
use std::io;
use byteorder::{LittleEndian, WriteBytesExt};


#[derive(Clone, Debug)]
pub struct TxOutpoint {
    pub tx_hash: [u8; 32],
    pub output_idx: u32,
}

#[derive(Clone, Debug)]
pub struct TxInput {
    pub outpoint: TxOutpoint,
    pub script: Script,
    pub sequence: u32,
}

#[derive(Clone, Debug)]
pub struct TxOutput {
    pub value: u64,
    pub script: Script,
}

#[derive(Clone, Debug)]
pub struct Tx {
    version: i32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    lock_time: u32,
}

pub fn tx_hex_to_hash(bytes: &[u8]) -> String {
    let mut tx_hash = [0; 32];

    // Ensure the input bytes are of the expected length (32 bytes).
    if bytes.len() == 32 {
        // Copy the bytes into tx_hash and reverse them to handle endianness.
        tx_hash.copy_from_slice(bytes);

        // Convert the byte array to a hexadecimal string
        let hex_string = hex::encode(tx_hash);

        // Print the input and output for debugging
        //println!("Input bytes: {:?}", bytes);
        //println!("Tx hash: {:?}", hex_string);

        hex_string
    } else {
        // Handle error for unexpected length. You can return an error or panic.
        panic!("Expected 32-byte input for tx_hex_to_hash");
    }
}

impl TxInput {
    pub fn new(outpoint: TxOutpoint,
               script: Script,
               sequence: u32) -> Self {
        TxInput { outpoint, script, sequence }
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> io::Result<()> {
        write.write(&self.outpoint.tx_hash)?;
        write.write_u32::<LittleEndian>(self.outpoint.output_idx)?;
        let script = self.script.to_vec();
        write_var_int(write, script.len() as u64)?;
        write.write(&script)?;
        write.write_u32::<LittleEndian>(self.sequence)?;
        Ok(())
    }
}

impl TxOutput {
    pub fn new(value: u64,
               script: Script) -> Self {
        TxOutput { value, script }
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> io::Result<()> {
        write.write_u64::<LittleEndian>(self.value)?;
        let script = self.script.to_vec();
        write_var_int(write, script.len() as u64)?;
        write.write(&script)?;
        Ok(())
    }
}

impl Tx {
    pub fn new(version: i32,
               inputs: Vec<TxInput>,
               outputs: Vec<TxOutput>,
               lock_time: u32) -> Self {
        Tx { version, inputs, outputs, lock_time }
    }

    pub fn write_to_stream<W: io::Write>(&self, write: &mut W) -> io::Result<()> {
        write.write_i32::<LittleEndian>(self.version)?;
        write_var_int(write, self.inputs.len() as u64)?;
        for input in self.inputs.iter() {
            input.write_to_stream(write)?;
        }
        write_var_int(write, self.outputs.len() as u64)?;
        for output in self.outputs.iter() {
            output.write_to_stream(write)?;
        }
        write.write_u32::<LittleEndian>(self.lock_time)?;
        Ok(())
    }

    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }   
        
}
