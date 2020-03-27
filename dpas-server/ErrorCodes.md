# Error Codes Returned by the Server

| Status Code       | Status Description           | Explanation of Error                                                         |
|-------------------|------------------------------|------------------------------------------------------------------------------|
| INVALID_ARGUMENT  | PublicKey                    | The public key could not be deserialised on the server                       |
| PERMISSION_DENIED | ClientNotRegistered          | The client wasn't registered yet                                             |
| PERMISSION_DENIED | TargetClientNotRegistered    | The read target client wasn't registered yet                                 |
| PERMISSION_DENIED | ClientRequestNotFresh        | The request received from the client wasn't fresh                            |
| PERMISSION_DENIED | ClientSignatureInvalid       | The signature of the request wasn't valid                                    |
| PERMISSION_DENIED | ClientIntegrityViolation     | The integrity of the request was violated                                    |
| PERMISSION_DENIED | AnnouncementSignatureInvalid | The signature of the announcement was invalid                                |
| UNAUTHENTICATED   | SessionNotInitiated          | The client hasn't initiated a session with the server yet (or it is invalid) |
