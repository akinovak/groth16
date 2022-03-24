use crate::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, rerandomize_proof,
    verify_proof,
};
use ark_ec::PairingEngine;
use ark_ff::UniformRand;
use ark_std::test_rng;

use core::ops::MulAssign;

use ark_ff::{Field, Zero};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
    x: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        let x = cs.new_input_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        // cs.enforce_constraint(lc!() + x, lc!(), lc!())?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

fn test_malleable_proof<E>()
where
    E: PairingEngine,
{
    let rng = &mut test_rng();

    let params =
        generate_random_parameters::<E, _, _>(MySillyCircuit { a: None, b: None, x: None }, rng).unwrap();

    let pvk = prepare_verifying_key::<E>(&params.vk);

    let a = E::Fr::from(2 as u64);
    let b = E::Fr::from(2 as u64);
    let x = E::Fr::from(1 as u64);

    let c = E::Fr::from(4 as u64);

    let proof = create_random_proof(
        MySillyCircuit {
            a: Some(a),
            b: Some(b),
            x: Some(x)
        },
        &params,
        rng,
    )
    .unwrap();

    assert!(verify_proof(&pvk, &proof, &[c, a]).unwrap());
}


mod bls12_377 {
    use super::{test_malleable_proof};
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        test_malleable_proof::<Bls12_377>();
    }
}