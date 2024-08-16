use crate::{
    functional::ApplyExt,
    mem::{SwapWithDefaultExt, SwapWithExt},
};

#[derive(thiserror::Error, Debug)]
pub enum ConstructionSiteErectError<E> {
    #[error("Construction site is void")]
    IsVoid,
    #[error("Construction is already built")]
    AlreadyBuilt,
    #[error("Other construction site error {0:?}")]
    Other(#[from] E),
}

pub trait Build<T>: Sized {
    type Error;
    fn build(self) -> Result<T, Self::Error>;
}

#[derive(Debug)]
pub enum ConstructionSite<Builder, T>
where
    Builder: Build<T>,
{
    Void,
    Builder(Builder),
    Product(T),
}

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
    pub fn void() -> Self {
        Self::Void
    }

    pub fn new(builder: Builder) -> Self {
        Self::Builder(builder)
    }

    pub fn from_product(value: T) -> Self {
        Self::Product(value)
    }

    pub fn take(&mut self) -> Self {
        self.swap_with_default()
    }

    pub fn modify_taken_with_return<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(Self) -> (Self, R),
    {
        let (site, res) = self.take().apply(f);
        self.swap_with(site);
        res
    }

    pub fn modify_taken<F>(&mut self, f: F)
    where
        F: FnOnce(Self) -> Self,
    {
        self.take().apply(f).swap_with_mut(self)
    }

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
    #[must_use]
    pub fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }

    /// Returns `true` if the construction site is [`InProgress`].
    ///
    /// [`InProgress`]: ConstructionSite::InProgress
    #[must_use]
    pub fn in_progess(&self) -> bool {
        matches!(self, Self::Builder(..))
    }

    /// Returns `true` if the construction site is [`Done`].
    ///
    /// [`Done`]: ConstructionSite::Done
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Product(..))
    }

    pub fn into_builder(self) -> Option<Builder> {
        use ConstructionSite as S;
        match self {
            S::Builder(v) => Some(v),
            _ => None,
        }
    }

    pub fn builder_ref(&self) -> Option<&Builder> {
        use ConstructionSite as S;
        match self {
            S::Builder(v) => Some(v),
            _ => None,
        }
    }

    pub fn builder_mut(&mut self) -> Option<&mut Builder> {
        use ConstructionSite as S;
        match self {
            S::Builder(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_product(self) -> Option<T> {
        use ConstructionSite as S;
        match self {
            S::Product(v) => Some(v),
            _ => None,
        }
    }

    pub fn product_ref(&self) -> Option<&T> {
        use ConstructionSite as S;
        match self {
            S::Product(v) => Some(v),
            _ => None,
        }
    }

    pub fn product_mut(&mut self) -> Option<&mut T> {
        use ConstructionSite as S;
        match self {
            S::Product(v) => Some(v),
            _ => None,
        }
    }
}
