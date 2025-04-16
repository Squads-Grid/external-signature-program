use pinocchio::pubkey::Pubkey;



// pub struct ExecutableInstructions<'a, T>
// where
//     T: Deref<Target = [u8]>,
// {
//     data: T,
// }

// impl<'a, T> Instructions<T>
// where
//     T: Deref<Target = [u8]> + 'a,
// {
//     pub fn load_instruction_at(index: usize) -> Result<IntrospectedInstruction, ProgramError> {
//         // The first 1 byte of instructions data is the total number of instructions
//         let num_instructions = unsafe { *(self.data.as_ptr() as *const u8) };
//         if index >= num_instructions as usize {
//             return Err(ProgramError::InvalidInstructionData);
//         }
//         // The next 1 byte is the header of the instruction
//         let header = unsafe { &self.data[index * size_of::<InstructionHeader>()] };
//         todo!()
//     }
// }

// #[repr(C)]
// pub struct InstructionHeader {
//     pub accounts_len: u8,
//     pub data_len: u32
// }

// #[repr(C)]
// pub struct CustomCompiledInstruction<'a>{
//     pub program_id_index: u8,
//     pub num_accounts: u8,
//     pub accounts_indices: &'a [u8],
//     pub data_len: u8,
//     pub data: &'a [u8],
// }



