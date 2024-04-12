use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Finite, Interval, IntervalBound, PositiveInfinity}
use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Output, ScriptContext, Spend, Transaction, find_input,
}
use aiken/transaction/credential.{ScriptCredential, VerificationKey}
use aiken/transaction/value.{PolicyId}
use vester/tx

type PosixTime =
  Int

type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

// todo change the name
type DatumType {
  start_time: PosixTime,
  day: Int,
  owner: VerificationKeyHash,
  token_policy: PolicyId,
  token_name: ByteArray,
}

validator {
  fn unlock(datum: DatumType, _r: Void, ctx: ScriptContext) {
    let ScriptContext { purpose, transaction } = ctx
    let Transaction { inputs, outputs, validity_range, extra_signatories, .. } =
      transaction
    when purpose is {
      Spend(ref) -> {
        expect Some(this_input) = find_input(inputs, ref)
        let this_address = this_input.output.address

        // it must be signed by the owner
        expect list.has(extra_signatories, datum.owner)

        // only one input of this address allowed
        expect [only_input] =
          list.filter(
            inputs,
            fn(input) { input.output.address == this_address },
          )

        // get current time
        expect Finite(now) = validity_range.lower_bound.bound_type

        // now should be more than start time 
        expect now >= datum.start_time

        // days should be bigger than the last unlock day
        let days = ( now - datum.start_time ) / ( 1000 * 60 * 60 * 24 )
        expect days > datum.day

        let current_day = datum.day + 1

        let input_amount =
          value.quantity_of(
            only_input.output.value,
            datum.token_policy,
            datum.token_name,
          )

        let unlock_amount = current_day * 20_000

        if unlock_amount < input_amount {
          expect [only_output] =
            list.filter(outputs, fn(output) { output.address == this_address })

          let output_amount =
            value.quantity_of(
              only_output.value,
              datum.token_policy,
              datum.token_name,
            )

          expect output_amount == input_amount - unlock_amount

          // increment the datum day
          expect InlineDatum(input_data) = only_input.output.datum
          expect input_datum: DatumType = input_data
          expect InlineDatum(output_data) = only_output.datum
          expect output_datum: DatumType = output_data
          output_datum == DatumType { ..input_datum, day: input_datum.day + 1 }
        } else {
          // if the amount that we are unlocking is greater than what is in the input
          // it means that we are at the end of vesting period and it is ok to unlock
          // whatever is left
          True
        }
      }

      _ -> False
    }
  }
}

// this succeeds because it meets all the requirements
test unlock_01() {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 0,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(DatumType { ..datum, day: datum.day + 1 }),
    )
  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input])
      |> tx.set_outputs([this_output])
      |> tx.set_extra_signatories(["me"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}

// this fails because it has more input of the same address
test unlock_02() fail {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 0,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_input_2 =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.zero(),
        InlineDatum(datum),
      ),
    )

  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(DatumType { ..datum, day: datum.day + 1 }),
    )
  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input, this_input_2])
      |> tx.set_outputs([this_output])
      |> tx.set_extra_signatories(["me"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}

// this fails because it has more output of the same address
test unlock_03() fail {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 0,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(DatumType { ..datum, day: datum.day + 1 }),
    )
  let this_output_2 =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.zero(),
      InlineDatum(DatumType { ..datum, day: datum.day + 1 }),
    )

  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input])
      |> tx.set_outputs([this_output, this_output_2])
      |> tx.set_extra_signatories(["me"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}

// this fails because it is not signed by the owner
test unlock_04() fail {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 0,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(DatumType { ..datum, day: datum.day + 1 }),
    )

  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input])
      |> tx.set_outputs([this_output])
      |> tx.set_extra_signatories(["somebody"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}

// this fails because no days has passed since the last unlock
test unlock_05() fail {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 2,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(DatumType { ..datum, day: datum.day + 1 }),
    )

  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input])
      |> tx.set_outputs([this_output])
      |> tx.set_extra_signatories(["me"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}

// this fails because datum does not increase the day
test unlock_06() fail {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 0,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(
        DatumType {
          start_time: 1,
          day: 0,
          owner: "me",
          token_policy: "policy",
          token_name: "name",
        },
      ),
    )

  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input])
      |> tx.set_outputs([this_output])
      |> tx.set_extra_signatories(["me"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}

// this fails because datum changes in a way that is shouldn't
test unlock_07() fail {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 0,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(
        DatumType {
          start_time: 1,
          day: 1,
          owner: "somebody",
          token_policy: "policy",
          token_name: "name",
        },
      ),
    )

  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input])
      |> tx.set_outputs([this_output])
      |> tx.set_extra_signatories(["me"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}

// datum.day + 1 dtermines the unlock amount even if we are waaay past that day
test unlock_08() {
  let this_ref = tx.make_ref("this_ref", 0)
  let datum =
    DatumType {
      start_time: 1,
      day: 0,
      owner: "me",
      token_policy: "policy",
      token_name: "name",
    }
  let this_input =
    tx.make_input(
      this_ref,
      tx.make_output(
        tx.make_address(ScriptCredential("this_address")),
        value.add(value.zero(), "policy", "name", 1_000_000),
        InlineDatum(datum),
      ),
    )
  let this_output =
    tx.make_output(
      tx.make_address(ScriptCredential("this_address")),
      value.add(value.zero(), "policy", "name", 1_000_000 - 20_000),
      InlineDatum(
        DatumType {
          start_time: 1,
          day: 1,
          owner: "me",
          token_policy: "policy",
          token_name: "name",
        },
      ),
    )

  let transaction =
    tx.empty()
      |> tx.set_inputs([this_input])
      |> tx.set_outputs([this_output])
      |> tx.set_extra_signatories(["me"])
      |> tx.set_validity_range(
          Interval {
            lower_bound: IntervalBound {
              bound_type: Finite(1000 * 60 * 60 * 24 * 10 + 2),
              is_inclusive: True,
            },
            upper_bound: IntervalBound {
              bound_type: PositiveInfinity,
              is_inclusive: False,
            },
          },
        )
  let context = ScriptContext(transaction, Spend(this_ref))

  unlock(datum, Void, context)
}
