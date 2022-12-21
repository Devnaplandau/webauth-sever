const {
  //  register
  generateRegistrationOptions,
  verifyRegistrationResponse,
  // authen
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

// Human-readable title for your website
const rpName = "Demo Example";
// A unique identifier for your website
// const rpID = "webauthen-teknix.vercel.app";
const rpID = "localhost";
// The URL at which registrations and authentications should occur
function serverMakeCredPlat(user) {
  let userAuthenticators = user.authenticators;

  return generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: user.name,
    userEmail: user.email,
    // Don't prompt users for additional information about the authenticator
    // (Recommended for smoother UX)
    attestationType: "direct",
    // Prevent users from re-registering existing authenticators
    excludeCredentials: userAuthenticators
      ? userAuthenticators.map((authenticator) => ({
          id: authenticator.credentialID,
          type: "public-key",
          // Optional
          transports: authenticator.transports,
        }))
      : [],
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
    },
  });
}

function serverMakeCredPCross(user) {
  let userAuthenticators = user.authenticators;

  return generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: user.name,
    userEmail: user.email,
    // Don't prompt users for additional information about the authenticator
    // (Recommended for smoother UX)
    attestationType: "none",
    // Prevent users from re-registering existing authenticators
    excludeCredentials: userAuthenticators
      ? userAuthenticators.map((authenticator) => ({
          id: authenticator.credentialID,
          type: "public-key",
          // Optional
          transports: authenticator.transports,
        }))
      : [],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
    },
  });
}
module.exports = {
  serverMakeCredPlat,
  serverMakeCredPCross,
};
