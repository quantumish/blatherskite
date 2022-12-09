use poem::http::StatusCode;
use diesel::result::{QueryResult, Error};

#[derive(Debug, Clone)]
pub struct UserFacingPropagatedError {
	code: StatusCode,
	backtrace: Option<String>,
	error_kind: String,
	error: String,
	context: Option<String>,
}

impl std::fmt::Display for UserFacingPropagatedError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		writeln!(f, "<h1>{}</h1>", self.code)?;
		writeln!(f, "Received <code>{}: {}</code>", self.error_kind, self.error)?;
		if let Some(ctx) = &self.context {
			writeln!(f, " while {}.", ctx)?;
		}
		if let Some(trace) = &self.backtrace {
			writeln!(f, "<pre>{}</pre>", html_escape::encode_text(&trace))?;
		}
		Ok(())
	}
}

impl std::error::Error for UserFacingPropagatedError {}

#[derive(Debug, Clone)]
pub struct UserFacingError {
	code: StatusCode,
	reason: Option<String>,
}

impl UserFacingError {
	pub fn new(code: StatusCode, reason: &str) -> Self {
		Self {
			code,
			reason: Some(String::from(reason))
		}
	}
	pub fn terse(code: StatusCode) -> Self {
		Self {
			code,
			reason: None,
		}
	}
}

impl Into<poem::Error> for UserFacingError {
	fn into(self) -> poem::Error {
		let code = self.code;
		poem::Error::new(self, code)
	}
}

impl std::fmt::Display for UserFacingError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "<h1>{}</h1>", self.code)?;
		if let Some(reason) = &self.reason {
			write!(f, "{}", reason)?;
		}
		writeln!(f, "")
	}
}

impl std::error::Error for UserFacingError {}

#[derive(Debug)]
pub struct WithBacktrace<E>
where E: std::error::Error
{
	backtrace: std::backtrace::Backtrace,
	pub err: E,
	pub context: Option<String>,
}

impl<E> std::fmt::Display for WithBacktrace<E>
	where E: std::error::Error
{
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", self.err)
	}
}

impl<E> std::error::Error for WithBacktrace<E>
where E: std::error::Error  {}

pub trait WithBacktraceExt<E> where E: std::error::Error  {
	type Success;
	fn with_backtrace(self) -> Result<Self::Success, WithBacktrace<E>>;
}

impl<T,E> WithBacktraceExt<E> for Result<T, E>
where E: std::error::Error
{
	type Success = T;
	fn with_backtrace(self) -> Result<Self::Success, WithBacktrace<E>> {
		self.map_err(|err| WithBacktrace {
			err,
			backtrace: std::backtrace::Backtrace::capture(),
			context: None
		})
	}
}

pub trait InternalResultExt {
	type Success;
	fn poemify(self, ctx: &str) -> poem::Result<Self::Success>;
}


#[derive(Debug)]
pub struct StdAnyhowError(pub anyhow::Error);

impl std::fmt::Display for StdAnyhowError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		std::fmt::Display::fmt(&self.0, f)
	}
}

impl std::error::Error for StdAnyhowError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(self.0.as_ref())
	}
}

impl From<anyhow::Error> for StdAnyhowError {
	fn from(err: anyhow::Error) -> Self {
		Self(err)
	}
}

impl<T> InternalResultExt for QueryResult<T> {
	type Success = T;

	fn poemify(self, ctx: &str) -> poem::Result<Self::Success> {
		self.map_err(|err| {
			log::error!("{:#?}", err);
			let code = match err {
				diesel::result::Error::NotFound => StatusCode::NOT_FOUND,
				_ => StatusCode::INTERNAL_SERVER_ERROR,
			};
			poem::error::Error::new(UserFacingPropagatedError {
				code,
				backtrace: None,
				context: Some(String::from(ctx)),
				error_kind: format!("{:?}", err),
				error: err.to_string(),
			}, code)
		})
	}
}


impl<T> InternalResultExt for anyhow::Result<T> {
	type Success = T;

	fn poemify(self, ctx: &str) -> poem::Result<Self::Success> {
		self.map_err(|err| {
			log::error!("{:#?}", err);
			poem::error::InternalServerError(StdAnyhowError::from(err))
		})
	}

}

impl<T, E> InternalResultExt for std::result::Result<T, WithBacktrace<E>>
	where E: std::error::Error
{
	type Success = T;

	fn poemify(self, ctx: &str) -> poem::Result<Self::Success> {
		self.map_err(|err| {
			log::error!("{:#?}", err.err);
			poem::error::InternalServerError( UserFacingPropagatedError {
				code: StatusCode::INTERNAL_SERVER_ERROR,
				backtrace: Some(err.backtrace.to_string()),
				context: Some(String::from(ctx)),
				error_kind: String::from(std::any::type_name::<E>()),
				error: err.to_string(),
			})
		})
	}

}
