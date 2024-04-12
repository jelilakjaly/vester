use aiken/dict
use aiken/hash.{Blake2b_256, Hash}
use aiken/interval
use aiken/transaction.{
  Datum, Input, Output, OutputReference, Transaction, TransactionId,
  ValidityRange,
}
use aiken/transaction/credential.{Address, Credential, VerificationKey}
use aiken/transaction/value.{Value}

pub fn empty() -> Transaction {
  Transaction {
    inputs: [],
    reference_inputs: [],
    outputs: [],
    fee: value.zero(),
    mint: value.zero() |> value.to_minted_value(),
    certificates: [],
    withdrawals: dict.new(),
    validity_range: interval.everything(),
    extra_signatories: [],
    redeemers: dict.new(),
    datums: dict.new(),
    id: TransactionId {
      hash: #"0000000000000000000000000000000000000000000000000000000000000000",
    },
  }
}

pub fn set_inputs(tx: Transaction, inputs: List<Input>) -> Transaction {
  Transaction { ..tx, inputs: inputs }
}

pub fn set_outputs(tx: Transaction, outputs: List<Output>) -> Transaction {
  Transaction { ..tx, outputs: outputs }
}

pub fn set_mint(tx: Transaction, value: Value) -> Transaction {
  Transaction { ..tx, mint: value.to_minted_value(value) }
}

pub fn set_validity_range(
  tx: Transaction,
  validity_range: ValidityRange,
) -> Transaction {
  Transaction { ..tx, validity_range: validity_range }
}

pub fn set_extra_signatories(
  tx: Transaction,
  signatories: List<Hash<Blake2b_256, VerificationKey>>,
) -> Transaction {
  Transaction { ..tx, extra_signatories: signatories }
}

pub fn make_input(ref: OutputReference, output: Output) -> Input {
  Input { output_reference: ref, output }
}

pub fn make_output(address: Address, value: Value, datum: Datum) -> Output {
  Output { address, value, datum, reference_script: None }
}

pub fn make_address(credential: Credential) -> Address {
  Address { payment_credential: credential, stake_credential: None }
}

pub fn make_ref(
  hash: Hash<Blake2b_256, Transaction>,
  index: Int,
) -> OutputReference {
  OutputReference { transaction_id: TransactionId(hash), output_index: index }
}
