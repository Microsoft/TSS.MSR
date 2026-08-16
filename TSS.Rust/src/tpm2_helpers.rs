/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

use crate::{tpm_buffer::TpmBuffer, tpm_types::ENUM_TO_STR_MAP};

/// Convert a numeric enum value to its string representation
///
/// # Arguments
///
/// * `enum_val` - The numeric value of the enum
/// * `enum_id` - The identifier of the enum type
///
/// # Returns
///
/// The string representation of the enum value, or a formatted string of OR'd values
pub fn enum_to_str(enum_val: u64, enum_id: std::any::TypeId) -> String {
    let mut res = String::new();

    // Try to find the exact enum value in the map
    if let Some(enum_map) = ENUM_TO_STR_MAP.get(&enum_id) {
        if let Some(name) = enum_map.get(&enum_val) {
            return name.to_string();
        }

        // If not found as an exact match, try to decompose as bit flags
        let mut cur_bit: u64 = 1;
        let mut found_bits: u64 = 0;

        while (found_bits != enum_val) {
            if (cur_bit & enum_val) != 0 {
                found_bits |= cur_bit;

                if !res.is_empty() {
                    res.push_str(" | ");
                }

                if let Some(bit_name) = enum_map.get(&cur_bit) {
                    res.push_str(bit_name);
                }
            }

            cur_bit <<= 1;
        }
    }

    res // Return empty string if enum ID is not found
}

pub fn int_to_tpm<T: Into<u64>>(val: T) -> Vec<u8> {
    let mut buffer = TpmBuffer::new(None);
    buffer.write_num(val.into(), std::mem::size_of::<T>());
    buffer.trim().to_vec()
}