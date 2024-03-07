export class SDJWTError extends Error {
  constructor(message: any) {
    super(message);
  }
}

export class SplitSDJWTError extends SDJWTError {
  constructor(message: any) {
    super(message);
  }
}

export class DecodeJWTError extends SDJWTError {
  constructor(message: any) {
    super(message);
  }
}

export class DecodeSDJWTError extends SDJWTError {
  constructor(message: any) {
    super(message);
  }
}

export class IssueSDJWTError extends SDJWTError {
  constructor(message: any) {
    super(message);
  }
}

export class VerifySDJWTError extends SDJWTError {
  constructor(message: any) {
    super(message);
  }
}

export class PackSDJWTError extends SDJWTError {
  constructor(message: any) {
    super(message);
  }
}

export class CreateDecoyError extends SDJWTError {
  constructor(message: any) {
    super(message);
  }
}
