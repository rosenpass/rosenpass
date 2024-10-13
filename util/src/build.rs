//! Lazy construction of values

use crate::{
    functional::ApplyExt,
    mem::{SwapWithDefaultExt, SwapWithExt},
};

/// Errors returned by [ConstructionSite::erect]
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum ConstructionSiteErectError<E> {
    /// Attempted to erect an empty construction site
    #[error("Construction site is void")]
    IsVoid,
    /// Attempted to erect a construction that is already standing
    #[error("Construction is already built")]
    AlreadyBuilt,
    /// Other error
    #[error("Other construction site error {0:?}")]
    Other(#[from] E),
}

/// A type that can build some other type
///
/// # Examples
///
/// ```
/// use rosenpass_util::build::Build;
/// use anyhow::{Context, Result};
///
/// #[derive(Eq, PartialEq, Debug)]
/// struct Person {
///     pub fav_pokemon: String,
///     pub fav_number: u8,
/// }
///
/// #[derive(Default, Clone)]
/// struct PersonBuilder {
///     pub fav_pokemon: Option<String>,
///     pub fav_number: Option<u8>,
/// }
///
/// impl Build<Person> for &PersonBuilder {
///     type Error = anyhow::Error;
///
///     fn build(self) -> Result<Person, Self::Error> {
///         let fav_pokemon = self.fav_pokemon.clone().context("Missing fav pokemon")?;
///         let fav_number = self.fav_number.context("Missing fav number")?;
///         Ok(Person {
///             fav_pokemon,
///             fav_number,
///         })
///     }
/// }
///
/// let mut person_builder = PersonBuilder::default();
/// assert!(person_builder.build().is_err());
///
/// person_builder.fav_pokemon = Some("Krabby".to_owned());
/// person_builder.fav_number = Some(0);
/// assert_eq!(
///     person_builder.build().unwrap(),
///     Person {
///         fav_pokemon: "Krabby".to_owned(),
///         fav_number: 0
///     }
/// );
/// ```
pub trait Build<T>: Sized {
    /// Error returned by the builder
    type Error;
    /// Build the type
    ///
    /// # Examples
    ///
    /// See [Self].
    fn build(self) -> Result<T, Self::Error>;
}

/// A type that can be incrementally built from a type that can [Build] it
///
/// This is similar to an option, where [Self::Void] is [std::Option::None],
/// [Self::Product] is [std::Option::Some], except that there is a third
/// intermediate state [Self::Builder] that represents a Some/Product value
/// in the process of being made.
///
/// # Examples
///
/// ```
/// use std::borrow::Borrow;
/// use rosenpass_util::build::{ConstructionSite, Build};
/// use anyhow::{Context, Result};
///
/// #[derive(Eq, PartialEq, Debug)]
/// struct Person {
///     pub fav_pokemon: String,
///     pub fav_number: u8,
/// }
///
/// #[derive(Eq, PartialEq, Default, Clone, Debug)]
/// struct PersonBuilder {
///     pub fav_pokemon: Option<String>,
///     pub fav_number: Option<u8>,
/// }
///
/// impl Build<Person> for &PersonBuilder {
///     type Error = anyhow::Error;
///
///     fn build(self) -> Result<Person, Self::Error> {
///         let fav_pokemon = self.fav_pokemon.clone().context("Missing fav pokemon")?;
///         let fav_number = self.fav_number.context("Missing fav number")?;
///         Ok(Person {
///             fav_pokemon,
///             fav_number,
///         })
///     }
/// }
///
/// impl Build<Person> for PersonBuilder {
///     type Error = anyhow::Error;
///
///     fn build(self) -> Result<Person, Self::Error> {
///          self.borrow().build()
///     }
/// }
///
/// // Allocate the construction site
/// let mut site = ConstructionSite::void();
///
/// // Start construction
/// site = ConstructionSite::Builder(PersonBuilder::default());
///
/// // Use the builder to build the value
/// site.builder_mut().unwrap().fav_pokemon = Some("Krabby".to_owned());
/// site.builder_mut().unwrap().fav_number = Some(0);
///
/// // Use `erect` to call Build::build
/// site.erect();
///
/// assert_eq!(
///     site,
///     ConstructionSite::Product(Person {
///         fav_pokemon: "Krabby".to_owned(),
///         fav_number: 0
///     }),
/// );
/// ```
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ConstructionSite<Builder, T>
where
    Builder: Build<T>,
{
    /// The site is empty
    Void,
    /// The site is being built
    Builder(Builder),
    /// The site has been built and is now finished
    Product(T),
}

/// Initializes the construction site as [ConstructionSite::Void]
impl<Builder, T> Default for ConstructionSite<Builder, T>
where
    Builder: Build<T>,
{
    fn default() -> Self {
        Self::Void
    }
}

impl<Builder, T> ConstructionSite<Builder, T>
where
    Builder: Build<T>,
{
    /// Initializes the construction site as [ConstructionSite::Void]
    ///
    /// # Examples
    ///
    /// See [Self].
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// assert_eq!(
    ///     ConstructionSite::<Builder, House>::void(),
    ///     ConstructionSite::Void,
    /// );
    /// ```
    pub fn void() -> Self {
        Self::Void
    }

    /// Initialize the construction site from its builder
    ///
    /// # Examples
    ///
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// assert_eq!(
    ///     ConstructionSite::<Builder, House>::new(Builder),
    ///     ConstructionSite::Builder(Builder),
    /// );
    /// ```
    pub fn new(builder: Builder) -> Self {
        Self::Builder(builder)
    }

    /// Initialize the construction site from its product
    ///
    /// # Examples
    ///
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// assert_eq!(
    ///     ConstructionSite::<Builder, House>::from_product(House),
    ///     ConstructionSite::Product(House),
    /// );
    /// ```
    pub fn from_product(value: T) -> Self {
        Self::Product(value)
    }

    /// Extract the construction site and replace it with [Self::Void]
    ///
    /// # Examples
    ///
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// let mut a = ConstructionSite::<Builder, House>::from_product(House);
    /// let a_backup = a.clone();
    ///
    /// let b = a.take();
    /// assert_eq!(a, ConstructionSite::void());
    /// assert_eq!(b, ConstructionSite::Product(House));
    /// ```
    pub fn take(&mut self) -> Self {
        self.swap_with_default()
    }

    /// Apply the given function to Self, temporarily converting
    /// the mutable reference into an owned value.
    ///
    /// This is useful if you have some function that needs to modify
    /// the construction site as an owned value but all you have is a reference.
    ///
    /// # Examples
    ///
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House(u32);
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder(u32);
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House(self.0))
    ///     }
    /// }
    ///
    /// #[derive(Debug, PartialEq, Eq)]
    /// enum FancyMatchState {
    ///     New,
    ///     Built,
    ///     Increment,
    /// };
    ///
    /// fn fancy_match(site: &mut ConstructionSite<Builder, House>, def: u32) -> FancyMatchState {
    ///      site.modify_taken_with_return(|site| {
    ///          use ConstructionSite as C;
    ///          use FancyMatchState as F;
    ///          let (prod, state) = match site {
    ///              C::Void              => (House(def), F::New),
    ///              C::Builder(b)        => (b.build().unwrap(), F::Built),
    ///              C::Product(House(v)) => (House(v + 1), F::Increment),
    ///          };
    ///          let prod = ConstructionSite::from_product(prod);
    ///          (prod, state)
    ///      })
    /// }
    ///
    /// let mut a = ConstructionSite::void();
    /// let r = fancy_match(&mut a, 42);
    /// assert_eq!(a, ConstructionSite::Product(House(42)));
    /// assert_eq!(r, FancyMatchState::New);
    ///
    /// let mut a = ConstructionSite::new(Builder(13));
    /// let r = fancy_match(&mut a, 42);
    /// assert_eq!(a, ConstructionSite::Product(House(13)));
    /// assert_eq!(r, FancyMatchState::Built);
    ///
    /// let r = fancy_match(&mut a, 42);
    /// assert_eq!(a, ConstructionSite::Product(House(14)));
    /// assert_eq!(r, FancyMatchState::Increment);
    /// ```
    pub fn modify_taken_with_return<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(Self) -> (Self, R),
    {
        let (site, res) = self.take().apply(f);
        self.swap_with(site);
        res
    }

    /// Apply the given function to Self, temporarily converting
    /// the mutable reference into an owned value.
    ///
    /// This is useful if you have some function that needs to modify
    /// the construction site as an owned value but all you have is a reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House(u32);
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder(u32);
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House(self.0))
    ///     }
    /// }
    ///
    /// fn fancy_match(site: &mut ConstructionSite<Builder, House>, def: u32) {
    ///      site.modify_taken(|site| {
    ///          use ConstructionSite as C;
    ///          let prod = match site {
    ///              C::Void              => House(def),
    ///              C::Builder(b)        => b.build().unwrap(),
    ///              C::Product(House(v)) => House(v + 1),
    ///          };
    ///          ConstructionSite::from_product(prod)
    ///      })
    /// }
    ///
    /// let mut a = ConstructionSite::void();
    /// fancy_match(&mut a, 42);
    /// assert_eq!(a, ConstructionSite::Product(House(42)));
    ///
    /// let mut a = ConstructionSite::new(Builder(13));
    /// fancy_match(&mut a, 42);
    /// assert_eq!(a, ConstructionSite::Product(House(13)));
    ///
    /// fancy_match(&mut a, 42);
    /// assert_eq!(a, ConstructionSite::Product(House(14)));
    /// ```
    pub fn modify_taken<F>(&mut self, f: F)
    where
        F: FnOnce(Self) -> Self,
    {
        self.take().apply(f).swap_with_mut(self)
    }

    /// If this constructions site contains [Self::Builder], call the inner [Build]'s [Build::build]
    /// and have the construction site contain a product.
    ///
    /// # Examples
    ///
    /// See [Self].
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build, ConstructionSiteErectError};
    /// use std::convert::Infallible;
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = Infallible;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// let mut a = ConstructionSite::<Builder, House>::void();
    /// assert_eq!(a.erect(), Err(ConstructionSiteErectError::IsVoid));
    /// assert_eq!(a, ConstructionSite::void());
    ///
    /// let mut a = ConstructionSite::<Builder, House>::from_product(House);
    /// assert_eq!(a.erect(), Err(ConstructionSiteErectError::AlreadyBuilt));
    /// assert_eq!(a, ConstructionSite::from_product(House));
    ///
    /// let mut a = ConstructionSite::<Builder, House>::new(Builder);
    /// a.erect().unwrap();
    /// assert_eq!(a, ConstructionSite::from_product(House));
    /// ```
    #[allow(clippy::result_unit_err)]
    pub fn erect(&mut self) -> Result<(), ConstructionSiteErectError<Builder::Error>> {
        self.modify_taken_with_return(|site| {
            let builder = match site {
                site @ Self::Void => return (site, Err(ConstructionSiteErectError::IsVoid)),
                site @ Self::Product(_) => {
                    return (site, Err(ConstructionSiteErectError::AlreadyBuilt))
                }
                Self::Builder(builder) => builder,
            };

            let product = match builder.build() {
                Err(e) => {
                    return (Self::void(), Err(ConstructionSiteErectError::Other(e)));
                }
                Ok(p) => p,
            };

            (Self::from_product(product), Ok(()))
        })
    }

    /// Returns `true` if the construction site is [`Void`].
    ///
    /// [`Void`]: ConstructionSite::Void
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// type Site = ConstructionSite<Builder, House>;
    ///
    /// assert_eq!(Site::Void.is_void(), true);
    /// assert_eq!(Site::Builder(Builder).is_void(), false);
    /// assert_eq!(Site::Product(House).is_void(), false);
    /// ```
    #[must_use]
    pub fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }

    /// Returns `true` if the construction site is [`InProgress`].
    ///
    /// [`InProgress`]: ConstructionSite::InProgress
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// type Site = ConstructionSite<Builder, House>;
    ///
    /// assert_eq!(Site::Void.in_progress(), false);
    /// assert_eq!(Site::Builder(Builder).in_progress(), true);
    /// assert_eq!(Site::Product(House).in_progress(), false);
    /// ```
    #[must_use]
    pub fn in_progress(&self) -> bool {
        matches!(self, Self::Builder(..))
    }

    /// Returns `true` if the construction site is [`Done`].
    ///
    /// [`Done`]: ConstructionSite::Done
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// type Site = ConstructionSite<Builder, House>;
    ///
    /// assert_eq!(Site::Void.is_available(), false);
    /// assert_eq!(Site::Builder(Builder).is_available(), false);
    /// assert_eq!(Site::Product(House).is_available(), true);
    /// ```
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Product(..))
    }

    /// Returns the value of [Self::Builder]
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::build::{ConstructionSite, Build};
    ///
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct House;
    /// #[derive(Debug, Eq, PartialEq, Clone, Copy)]
    /// struct Builder;
    ///
    /// impl Build<House> for Builder {
    ///     type Error = anyhow::Error;
    ///
    ///     fn build(self) -> Result<House, Self::Error> {
    ///         Ok(House)
    ///     }
    /// }
    ///
    /// type Site = ConstructionSite<Builder, House>;
    ///
    /// assert_eq!(Site::Void.into_builder(), None);
    /// assert_eq!(Site::Builder(Builder).into_builder(), Some(Builder));
    /// assert_eq!(Site::Product(House).into_builder(), None);
    /// ```
    pub fn into_builder(self) -> Option<Builder> {
        use ConstructionSite as S;
        match self {
            S::Builder(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the value of [Self::Builder] as a reference
    ///
    /// # Examples
    ///
    /// See [Self::into_builder].
    pub fn builder_ref(&self) -> Option<&Builder> {
        use ConstructionSite as S;
        match self {
            S::Builder(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the value of [Self::Builder] as a mutable reference
    ///
    /// # Examples
    ///
    /// Similar to [Self::into_builder].
    pub fn builder_mut(&mut self) -> Option<&mut Builder> {
        use ConstructionSite as S;
        match self {
            S::Builder(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the value of [Self::Product]
    ///
    /// # Examples
    ///
    /// Similar to [Self::into_builder].
    pub fn into_product(self) -> Option<T> {
        use ConstructionSite as S;
        match self {
            S::Product(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the value of [Self::Product] as a reference
    ///
    /// # Examples
    ///
    /// Similar to [Self::into_builder].
    pub fn product_ref(&self) -> Option<&T> {
        use ConstructionSite as S;
        match self {
            S::Product(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the value of [Self::Product] as a mutable reference
    ///
    /// # Examples
    ///
    /// Similar to [Self::into_builder].
    pub fn product_mut(&mut self) -> Option<&mut T> {
        use ConstructionSite as S;
        match self {
            S::Product(v) => Some(v),
            _ => None,
        }
    }
}
