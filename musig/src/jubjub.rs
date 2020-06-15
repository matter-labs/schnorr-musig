use bellman::PrimeField;
use franklin_crypto::jubjub::{JubjubEngine, FixedGenerators, JubjubParams, Unknown};
use franklin_crypto::jubjub::edwards::Point;

pub struct JubJubWrapper<E: JubjubEngine>{
    pub params: <E as JubjubEngine>::Params,    
    pub generator: FixedGenerators,
}

impl<'t, E: JubjubEngine> JubJubWrapper<E>{
    pub fn new(
        params: <E as JubjubEngine>::Params,
        generator: FixedGenerators,
    ) -> Self{
        Self{
            params,
            generator,
        }
    }

    pub fn mul<S: Into<<E::Fs as PrimeField>::Repr>>(
        &self, 
        point: &Point<E, Unknown>, 
        scalar: S
    ) -> Point<E, Unknown>{
        point.mul(scalar, &self.params)
    }

    pub fn mul_by_generator(&self, scalar: E::Fs) -> Point<E, Unknown>{
        Point::from(
            self.params.generator(self.generator).mul(scalar, &self.params)
        )
    }

    pub fn mul_by_generator_ct(&self, scalar: E::Fs) -> Point<E, Unknown>{
        Point::from(
            self.params.generator(self.generator).mul_ct(scalar, &self.params)
        )
    }

    pub fn add(&self, p: &Point<E, Unknown>, q: &Point<E, Unknown>) -> Point<E, Unknown>{
        p.add(&q, &self.params)
    }

    pub fn is_in_correct_subgroup(&self, point: &Point<E, Unknown>) -> bool{
        if point.mul(E::Fs::char(), &self.params) == Point::zero() {
            return true
        } 
        false
    }

}
