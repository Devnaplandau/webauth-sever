const express = require("express");
const User = require("../models/user");

const otpGenerator = require("otp-generator");
const { Novu } = require("@novu/node");

const {
  serverMakeCredPlat,
  serverMakeCredPCross,
} = require("../helpers/userHelper");
const { randomBase64URLBuffer } = require("../helpers");

const base64url = require("base64url");

const {
  //  register
  generateRegistrationOptions,
  verifyRegistrationResponse,
  // authen
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const router = express.Router();

router.get("/", (req, res) => {
  res.send("dummy");
});

// Human-readable title for your website
const rpName = "Demo Example";
// A unique identifier for your website
// const rpID = "webauthen-teknix.vercel.app";
const rpID = "localhost";
// The URL at which registrations and authentications should occur
const origin = `http://${rpID}`;

router.post("/register", async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) return res.status(400).send("Missing email field");
    let userAuthenticators;
    const findUser = await User.findOne({ email });
    if (findUser) {
      return res.status(400).send("User already exists");
    }
    if (!findUser) {
      const user = await User.create({
        id: randomBase64URLBuffer(8),
        name: email.split("@")[0],
        email,
        role: "user",
      });
      user.save();

      const options = serverMakeCredPCross(user);
      options.status = "ok";

      req.session.challenge = options.challenge;
      req.session.email = email;

      return res.json(options);
    }
  } catch (e) {
    console.log(e);
    await User.deleteOne({ email });
    return res.status(200).send("Deleted");
  }
});

router.post("/registerAgain", async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) return res.status(400).send("Missing email field");
    const findUser = await User.findOne({ email });
    if (findUser) {
      return res.status(400).send("User already exists");
    }
    if (!findUser) {
      const user = await User.create({
        id: randomBase64URLBuffer(8),
        name: email.split("@")[0],
        email,
        role: "user",
      });
      user.save();

      const options = serverMakeCredPlat(user);
      options.status = "ok";

      req.session.challenge = options.challenge;
      req.session.email = email;

      return res.json(options);
    }
  } catch (e) {
    console.log(e);
    await User.deleteOne({ email });
    return res.status(200).send("Deleted");
  }
});

router.post("/registerfail", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("Missing email field");

  await User.deleteOne({ email });
  return res.status(200).send("Deleted");
});

router.post("/login", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json("Missing email field");
  const user = await User.findOne({ email });
  if (!user || user === null) {
    return res.status(400).send("User does not exist");
  } else if (user) {
    const userData = user.authenticators;
    const options = await generateAuthenticationOptions({
      allowCredentials: userData.map((authenticator) => ({
        id: base64url.toBuffer(authenticator.credentialID),
        type: "public-key",
        transports: authenticator.transports ? authenticator.transports : [],
      })),
      userVerification: "preferred",
    });

    options.rpId = rpID;
    options.status = "ok";
    console.log("options", options);
    req.session.challenge = options.challenge;
    req.session.email = email;
    return res.json(options);
  }
});

router.post("/verify-register", async (req, res) => {
  const { email } = req.session;
  let user = await User.findOne({ email });
  if (req.body.response?.attestationObject !== undefined) {
    const { body } = req;

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        credential: body,
        expectedChallenge: req.session.challenge,
        expectedOrigin: `${origin}:3000`,
        expectedRPID: rpID,
        requireUserVerification: true,
      });
      const { verified, registrationInfo } = verification;
      if (verified) {
        let { credentialID, credentialPublicKey, counter } = registrationInfo;
        // mã hóa để đưa lên mongodb
        credentialID = Buffer.from(credentialID, "base64url").toString(
          "base64url"
        );
        credentialPublicKey = Buffer.from(
          credentialPublicKey,
          "base64url"
        ).toString("base64url");

        if (req.body.otp) {
          user.authenticators = [];
          user.save();
        }

        user.authenticators.push({
          credentialID,
          credentialPublicKey,
          counter,
        });
        user.registered = verified;
        user.save();
        console.log("user save register done !", user);

        req.session.loggedIn = true;
        return res.json({ status: "ok" });
      } else {
        return res.json({
          status: "failed",
          message: "Can not authenticate signature!",
        });
      }
    } catch (error) {
      console.error(error);
      return res.status(400).send({ error: error.message });
    }
  }
});

router.post("/verify-authencations", async (req, res) => {
  const { email } = req.session;
  let user = await User.findOne({ email });
  if (req.body.response.authenticatorData !== undefined) {
    const { body } = req;

    const userAuth = user.authenticators;

    const arrAuth = {};
    // giải mã lại buffer để sử dụng dưới client
    userAuth.forEach((auth) => {
      arrAuth.credentialID = base64url.toBuffer(auth.credentialID);
      arrAuth.credentialPublicKey = base64url.toBuffer(
        auth.credentialPublicKey
      );
      arrAuth.counter = auth.counter ? auth.counter : auth.newCounter;
    });

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        credential: body,
        expectedChallenge: req.session.challenge,
        expectedOrigin: "http://localhost:3000",
        expectedRPID: rpID,
        authenticator: arrAuth,
      });

      const { verified, authenticationInfo } = verification;
      let { credentialID } = authenticationInfo;

      if (verified) {
        const authInfo = {
          ...authenticationInfo,
          credentialID: Buffer.from(credentialID, "base64url").toString(
            "base64url"
          ),
          credentialPublicKey: Buffer.from(
            arrAuth.credentialPublicKey,
            "base64url"
          ).toString("base64url"),
        };
        user.authenticators = authInfo;

        user.save();
        return res.json({ status: "ok" });
      }
    } catch (error) {
      console.error(error);
      return res.status(400).send({ error: error.message });
    }
  }
});

router.get("/profile", async (req, res) => {
  if (!req.session.loggedIn) return res.status(401).send("Denied!");

  const user = await User.findOne({ email: req.session.email });

  return res.json(user);
});

router.get("/logout", (req, res) => {
  req.session = null;
  return res.send("Logged out");
});

router.get("/getAllUser", async (req, res) => {
  try {
    const list = await User.find({}).sort("-createAt");
    res.status(200).json(list);
  } catch (error) {
    res.status(500).json(error);
  }
});

router.post("/send-otp", async (req, res) => {
  const novu = new Novu("cc31476446244ecf397a5f5c4d59f4df");
  const { email } = req.body;
  console.log(email);
  let user = await User.findOne({ email });

  if (!email) return res.status(400).send("Missing email field");

  if (!user || user === null) {
    return res.status(400).send("User does not exist");
  }

  const otp = otpGenerator.generate(4, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
  });

  const template = `<div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
  <div style="margin:50px auto;width:70%;padding:20px 0">
    <div style="border-bottom:1px solid #eee">
      <a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600">Your Brand</a>
    </div>
    <p style="font-size:1.1em">Hi,</p>
    <p>Thank you for choosing Your Brand. Use the following OTP to complete your Sign Up procedures. OTP is valid for 5 minutes</p>
    <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">${otp}</h2>
    <p style="font-size:0.9em;">Regards,<br />Your Brand</p>
    <hr style="border:none;border-top:1px solid #eee" />
    <div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300">
      <p>Your Brand Inc</p>
      <p>1600 Amphitheatre Parkway</p>
      <p>California</p>
    </div>
  </div>
</div>`;

  try {
    novu.trigger("recover-account", {
      to: {
        subscriberId: "OPT",
        email: email,
      },
      payload: {
        template: template,
      },
    });
  } catch (error) {
    console.log(error);
  }

  try {
    user.otp = otp;
    user.save();
  } catch (error) {
    console.log(error);
  }

  return res.status(200).send("Send OTP Successfully");
});

router.post("/confirm-otp", async (req, res) => {
  try {
    const { otp, email } = req.body;

    let user = await User.findOne({ email });

    if (user.otp !== otp) {
      return res.status(401).send("OTP is not Exits");
    }

    const options = generateRegistrationOptions({
      rpName,
      rpID,
      userID: user.id,
      userName: user.name,
      userEmail: user.email,
      // Don't prompt users for additional information about the authenticator
      // (Recommended for smoother UX)
      attestationType: "none",
      // Prevent users from re-registering existing authenticators
      excludeCredentials: [],
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
      },
    });
    options.status = "ok";

    req.session.challenge = options.challenge;
    req.session.email = email;

    return res.json(options);
  } catch (e) {
    return res.status(400).send("fail");
  }
});

module.exports = router;
