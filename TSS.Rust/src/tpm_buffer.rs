// Since all of the functions here are called from auto-generated code that expects a specific names,
// we have to use those names and not the Rust convention of snake_case
#![allow(non_snake_case)]

use crate::error::TpmError;
use crate::tpm_structure::TpmEnum;

pub struct SizedStructInfo {
    pub start_pos: usize,
    pub size: usize,
}

pub trait TpmMarshaller {
    /** Convert this object to its TPM representation and store it in the given marshaling buffer */
    fn toTpm(&self, buf: &mut TpmBuffer) -> Result<(), TpmError>;

    /** Populate this object from the TPM representation in the given marshaling buffer */
    fn initFromTpm(&mut self, buf: &mut TpmBuffer) -> Result<(), TpmError>;

    /** Convert this object to its complete TPM wire representation. */
    #[allow(non_snake_case)]
    fn toBytes(&self) -> Result<Vec<u8>, TpmError> {
        let mut buffer = TpmBuffer::new(None);
        self.toTpm(&mut buffer)?;
        if !buffer.isOk() {
            return Err(TpmError::BufferOverflow);
        }
        Ok(buffer.trim().to_vec())
    }
}

pub struct TpmBuffer {
    buf: Vec<u8>,
    pos: usize,
    out_of_bounds: bool,
    sized_struct_sizes: Vec<SizedStructInfo>,
}

impl TpmBuffer {
    /** Constructs output (default) or input marshaling buffer depending on the parameter. */
    pub fn new(capacity_or_src_buf: Option<&TpmBuffer>) -> Self {
        match capacity_or_src_buf {
            Some(src_buf) => TpmBuffer {
                buf: src_buf.buf.clone(),
                pos: src_buf.pos,
                out_of_bounds: false,
                sized_struct_sizes: Vec::new(),
            },
            None => TpmBuffer {
                buf: Vec::with_capacity(4096),
                pos: 0,
                out_of_bounds: false,
                sized_struct_sizes: Vec::new(),
            },
        }
    }

    pub fn from(src_buf: &[u8]) -> Self {
        TpmBuffer {
            buf: src_buf.to_vec(),
            pos: 0,
            out_of_bounds: false,
            sized_struct_sizes: Vec::new(),
        }
    }

    /** @return Reference to the backing byte buffer */
    pub fn buffer(&self) -> &Vec<u8> {
        &self.buf
    }

    /** @return Size of the backing byte buffer. */
    pub fn size(&self) -> usize {
        self.buf.len()
    }

    /** @return Current read/write position in the backing byte buffer. */
    pub fn current_pos(&self) -> usize {
        self.pos
    }

    /** Sets the current read/write position in the backing byte buffer. */
    pub fn set_current_pos(&mut self, new_pos: usize) {
        self.pos = new_pos;
        self.out_of_bounds = self.size() < new_pos;
    }

    /** @return True unless a previous read/write operation caused under/overflow correspondingly. */
    pub fn isOk(&self) -> bool {
        !self.out_of_bounds
    }

    /** Shrinks the backing byte buffer so that it ends at the current position */
    pub fn trim(&mut self) -> &Vec<u8> {
        self.buf.truncate(self.pos);
        &self.buf
    }

    pub fn getCurStuctRemainingSize(&self) -> usize {
        if let Some(ssi) = self.sized_struct_sizes.last() {
            return ssi
                .size
                .saturating_sub(self.pos.saturating_sub(ssi.start_pos));
        }
        0
    }

    fn check_len(&mut self, len: usize) -> bool {
        self.ensure_write_len(len)
    }

    fn ensure_write_len(&mut self, len: usize) -> bool {
        let Some(end_pos) = self.pos.checked_add(len) else {
            self.out_of_bounds = true;
            return false;
        };

        if self.buf.len() < end_pos {
            self.buf.resize(end_pos, 0);
        }
        true
    }

    fn check_read_len(&mut self, len: usize) -> bool {
        let Some(end_pos) = self.pos.checked_add(len) else {
            self.out_of_bounds = true;
            return false;
        };

        if let Some(ssi) = self.sized_struct_sizes.last() {
            let consumed = self.pos.saturating_sub(ssi.start_pos);
            let remaining = ssi.size.saturating_sub(consumed);
            if consumed > ssi.size || len > remaining {
                self.out_of_bounds = true;
                return false;
            }
        }

        if self.buf.len() < end_pos {
            self.out_of_bounds = true;
            return false;
        }
        true
    }

    fn remaining_len(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns whether `size` can be represented without truncation by a `prefix_len`-byte
    /// unsigned length field.
    fn size_fits_prefix(size: usize, prefix_len: usize) -> bool {
        let Some(bit_count) = prefix_len.checked_mul(8) else {
            return false;
        };
        if bit_count == 0 || bit_count > u64::BITS as usize {
            return false;
        }

        let max_size = if bit_count == u64::BITS as usize {
            u64::MAX
        } else {
            (1_u64 << bit_count) - 1
        };
        u64::try_from(size).is_ok_and(|size| size <= max_size)
    }

    pub fn check_status(&self) -> Result<(), TpmError> {
        if self.isOk() {
            Ok(())
        } else {
            Err(TpmError::BufferUnderflow)
        }
    }

    pub fn write_num(&mut self, val: u64, len: usize) {
        if len == 0 {
            return;
        }

        if !self.check_len(len) {
            return;
        }

        if len == 8 {
            self.buf[self.pos] = ((val >> 56) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 48) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 40) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 32) & 0xFF) as u8;
            self.pos += 1;
        }
        if len >= 4 {
            self.buf[self.pos] = ((val >> 24) & 0xFF) as u8;
            self.pos += 1;
            self.buf[self.pos] = ((val >> 16) & 0xFF) as u8;
            self.pos += 1;
        }
        if len >= 2 {
            self.buf[self.pos] = ((val >> 8) & 0xFF) as u8;
            self.pos += 1;
        }
        self.buf[self.pos] = (val & 0xFF) as u8;
        self.pos += 1;
    }

    pub fn read_num(&mut self, len: usize) -> u64 {
        if len == 0 {
            return 0;
        }

        if !self.check_read_len(len) {
            return 0;
        }

        let mut res: u64 = 0;
        if len == 8 {
            res += (self.buf[self.pos] as u64) << 56;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 48;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 40;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 32;
            self.pos += 1;
        }
        if len >= 4 {
            res += (self.buf[self.pos] as u64) << 24;
            self.pos += 1;
            res += (self.buf[self.pos] as u64) << 16;
            self.pos += 1;
        }
        if len >= 2 {
            res += (self.buf[self.pos] as u64) << 8;
            self.pos += 1;
        }
        res += self.buf[self.pos] as u64;
        self.pos += 1;
        res
    }

    pub fn write_num_at_pos(&mut self, val: u64, pos: usize, len: usize) {
        let cur_pos = self.pos;
        self.pos = pos;
        self.write_num(val, len);
        self.pos = cur_pos;
    }

    /** Writes the given 8-bit integer to this buffer */
    pub fn writeByte(&mut self, val: u8) {
        if self.ensure_write_len(1) {
            self.buf[self.pos] = val;
            self.pos += 1;
        }
    }

    /** Marshals the given 16-bit integer to this buffer. */
    pub fn writeShort(&mut self, val: u16) {
        self.write_num(val as u64, 2);
    }

    /** Marshals the given 32-bit integer to this buffer. */
    pub fn writeInt(&mut self, val: u32) {
        self.write_num(val as u64, 4);
    }

    /** Marshals the given 64-bit integer to this buffer. */
    pub fn writeInt64(&mut self, val: u64) {
        self.write_num(val, 8);
    }

    /** Reads a byte from this buffer. */
    pub fn readByte(&mut self) -> u8 {
        if self.check_read_len(1) {
            let val = self.buf[self.pos];
            self.pos += 1;
            return val;
        }
        0
    }

    /** Unmarshals a 16-bit integer from this buffer. */
    pub fn readShort(&mut self) -> u16 {
        self.read_num(2) as u16
    }

    /** Unmarshals a 32-bit integer from this buffer. */
    pub fn readInt(&mut self) -> u32 {
        self.read_num(4) as u32
    }

    /** Unmarshals a 64-bit integer from this buffer. */
    pub fn readInt64(&mut self) -> u64 {
        self.read_num(8)
    }

    /** Marshalls the given byte buffer with no length prefix. */
    pub fn writeByteBuf(&mut self, data: &[u8]) {
        let data_size = data.len();
        if data_size == 0 || !self.ensure_write_len(data_size) {
            return;
        }
        self.buf[self.pos..self.pos + data_size].copy_from_slice(data);
        self.pos += data_size;
    }

    /** Unmarshalls a byte buffer of the given size (no marshaled length prefix). */
    pub fn readByteBuf(&mut self, size: usize) -> Vec<u8> {
        if size == 0 {
            return Vec::new();
        }

        if !self.check_read_len(size) {
            return Vec::new();
        }

        let mut new_buf = Vec::with_capacity(size);
        for i in 0..size {
            new_buf.push(self.buf[self.pos + i]);
        }
        self.pos += size;
        new_buf
    }

    /** Marshalls the given byte buffer with a length prefix. */
    pub fn writeSizedByteBuf(&mut self, data: &[u8], size_len: usize) {
        // Reject the payload before narrowing its length into the wire-format prefix.
        if !Self::size_fits_prefix(data.len(), size_len) {
            self.out_of_bounds = true;
            return;
        }
        self.write_num(data.len() as u64, size_len);
        self.writeByteBuf(data);
    }

    /** Unmarshals a byte buffer from its size-prefixed representation in the TPM wire format. */
    pub fn readSizedByteBuf(&mut self, size_len: usize) -> Vec<u8> {
        let size = self.read_num(size_len) as usize;
        if !self.isOk() {
            return Vec::new();
        }
        self.readByteBuf(size)
    }

    pub fn createObj<T: TpmMarshaller + Default>(&mut self) -> Result<T, TpmError> {
        let mut new_obj = T::default();
        new_obj.initFromTpm(self)?;
        self.check_status()?;
        Ok(new_obj)
    }

    pub fn writeSizedObj<T: TpmMarshaller>(&mut self, obj: &T) -> Result<(), TpmError> {
        const LEN_SIZE: usize = 2; // Length of the object size is always 2 bytes
        if !self.ensure_write_len(LEN_SIZE) {
            return Ok(());
        }

        // Remember position to marshal the size of the data structure
        let size_pos = self.pos;
        // Account for the reserved size area
        self.pos += LEN_SIZE;
        // Marshal the object
        obj.toTpm(self)?;
        // Calc marshaled object len
        let obj_size = self.pos - (size_pos + LEN_SIZE);
        // Sized TPM objects always use a two-byte prefix; a larger body cannot be encoded.
        if !Self::size_fits_prefix(obj_size, LEN_SIZE) {
            self.out_of_bounds = true;
            return Err(TpmError::BufferOverflow);
        }
        // Marshal it in the appropriate position
        self.pos = size_pos;
        self.writeShort(obj_size as u16);
        self.pos += obj_size;

        Ok(())
    }

    pub fn readSizedObj<T: TpmMarshaller + Default>(
        &mut self,
        obj: &mut T,
    ) -> Result<(), TpmError> {
        let size = self.readShort();
        if !self.isOk() {
            return Err(TpmError::BufferUnderflow);
        }
        if size == 0 {
            return Ok(());
        }
        if !self.check_read_len(size as usize) {
            return Err(TpmError::BufferUnderflow);
        }

        if size as usize > self.remaining_len() {
            self.out_of_bounds = true;
            return Err(TpmError::BufferUnderflow);
        }

        let end_pos = self.pos + size as usize;
        self.sized_struct_sizes.push(SizedStructInfo {
            start_pos: self.pos,
            size: size as usize,
        });

        let result = obj.initFromTpm(self);

        self.sized_struct_sizes.pop();
        result?;
        self.check_status()?;
        if self.pos != end_pos {
            self.out_of_bounds = true;
            return Err(TpmError::BufferUnderflow);
        }
        Ok(())
    }

    pub fn writeObjArr<T: TpmMarshaller>(&mut self, arr: &[T]) -> Result<(), TpmError> {
        // Array counts are encoded as u32 and must not be truncated on 64-bit platforms.
        if !Self::size_fits_prefix(arr.len(), std::mem::size_of::<u32>()) {
            self.out_of_bounds = true;
            return Err(TpmError::BufferOverflow);
        }
        self.writeInt(arr.len() as u32);
        for elt in arr {
            if !self.isOk() {
                break;
            }
            elt.toTpm(self)?;
        }

        Ok(())
    }

    pub fn readObjArr<T: TpmMarshaller + Default>(
        &mut self,
        arr: &mut Vec<T>,
    ) -> Result<(), TpmError> {
        let len = self.readInt();
        if !self.isOk() {
            return Err(TpmError::BufferUnderflow);
        }
        if len == 0 {
            arr.clear();
            return Ok(());
        }

        let len = len as usize;
        if len > self.remaining_len() {
            self.out_of_bounds = true;
            return Err(TpmError::BufferUnderflow);
        }

        arr.resize_with(len, T::default);
        for elt in arr {
            if !self.isOk() {
                break;
            }
            elt.initFromTpm(self)?;
        }

        self.check_status()
    }

    pub fn writeValArr<T, U>(&mut self, arr: &[T], val_size: usize)
    where
        T: TpmEnum<U> + Default,
        U: Into<u64>,
    {
        // Length of the array size is always 4 bytes
        // Array counts are encoded as u32 and must not be truncated on 64-bit platforms.
        if !Self::size_fits_prefix(arr.len(), std::mem::size_of::<u32>()) {
            self.out_of_bounds = true;
            return;
        }
        self.writeInt(arr.len() as u32);
        for val in arr {
            if !self.isOk() {
                break;
            }
            self.write_num(val.get_value().into(), val_size);
        }
    }

    pub fn readValArr<T, U>(&mut self, arr: &mut Vec<T>, val_size: usize) -> Result<(), TpmError>
    where
        T: TpmEnum<U> + Default,
        U: Into<u64>,
    {
        // Length of the array size is always 4 bytes
        let len = self.readInt();
        if !self.isOk() {
            return Err(TpmError::BufferUnderflow);
        }
        if len == 0 {
            arr.clear();
            return Ok(());
        }

        let len = len as usize;
        let Some(byte_len) = len.checked_mul(val_size) else {
            self.out_of_bounds = true;
            return Err(TpmError::BufferUnderflow);
        };
        if val_size == 0 || byte_len > self.remaining_len() {
            self.out_of_bounds = true;
            return Err(TpmError::BufferUnderflow);
        }

        arr.resize_with(len, Default::default);

        for elt in arr {
            if !self.isOk() {
                break;
            }

            *elt = T::new_from_trait((self.read_num(val_size) as u32).into())?;
        }

        self.check_status()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_structure::TpmStructure;
    use crate::tpm_types::{TPM2B_DIGEST, TPM2B_PRIVATE, TPM_HANDLE};

    struct OversizedSizedObject;

    impl TpmMarshaller for OversizedSizedObject {
        fn toTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {
            buffer.writeByteBuf(&vec![0; u16::MAX as usize + 1]);
            Ok(())
        }

        fn initFromTpm(&mut self, _buffer: &mut TpmBuffer) -> Result<(), TpmError> {
            Ok(())
        }
    }

    struct SizedObjectWrapper;

    impl TpmMarshaller for SizedObjectWrapper {
        fn toTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {
            buffer.writeSizedObj(&OversizedSizedObject)
        }

        fn initFromTpm(&mut self, _buffer: &mut TpmBuffer) -> Result<(), TpmError> {
            Ok(())
        }
    }

    #[test]
    fn create_obj_rejects_zero_length_input() {
        let mut buffer = TpmBuffer::from(&[]);

        assert!(matches!(
            buffer.createObj::<TPM_HANDLE>(),
            Err(TpmError::BufferUnderflow)
        ));
        assert_eq!(buffer.size(), 0);
        assert_eq!(buffer.current_pos(), 0);
    }

    #[test]
    fn from_bytes_rejects_truncated_input() {
        let mut bytes = vec![0x12, 0x34];
        let mut handle = TPM_HANDLE::default();

        assert!(matches!(
            handle.fromBytes(&mut bytes),
            Err(TpmError::BufferUnderflow)
        ));
    }

    #[test]
    fn sized_byte_buffer_rejects_length_larger_than_remaining_input() {
        let mut buffer = TpmBuffer::from(&[0x00, 0x04, 0xAA]);

        assert!(matches!(
            buffer.createObj::<TPM2B_DIGEST>(),
            Err(TpmError::BufferUnderflow)
        ));
        assert_eq!(buffer.size(), 3);
        assert_eq!(buffer.current_pos(), 2);
    }

    #[test]
    fn to_bytes_rejects_sized_byte_buffer_larger_than_prefix() {
        let value = TPM2B_PRIVATE::new(&vec![0; u16::MAX as usize + 1]);

        assert!(matches!(value.toBytes(), Err(TpmError::BufferOverflow)));
    }

    #[test]
    fn to_bytes_rejects_sized_object_larger_than_prefix() {
        assert!(matches!(
            SizedObjectWrapper.toBytes(),
            Err(TpmError::BufferOverflow)
        ));
    }
}
