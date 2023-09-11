import "dotenv";
import express, { Application, Request, Response } from "express";

import helmet from "helmet";
import morgan from "morgan";

import Constants from "../src/constants.js";
import authRouter from "../src/services/auth/auth-router.js";
import userRouter from "../src/services/user/user-router.js";
import eventRouter from "../src/services/event/event-router.js";
import newsletterRouter from "../src/services/newsletter/newsletter-router.js";

import crypto, { Hmac } from "crypto";

const app: Application = express();

const key: string | undefined = process.env.JWT_KEY;
interface DecodeRequestModel {
	token: string,
	context: object
}

interface CustomRequest<T> extends Request {
	body: T
}

// Utility packages (detailed in the readme)
app.use(helmet());
app.use(morgan("dev"));

// Use express.json only if we're not running locally
const env: string = process.env?.VERCEL_ENV ?? "";
if (env == "preview" || env == "production") {
	app.use(express.json());
}

// Add routers for each sub-service
app.use("/auth/", authRouter);
app.use("/user/", userRouter);
app.use("/newsletter/", newsletterRouter);
app.use("/event/", eventRouter);

// Ensure that API is running
app.get("/", (_: Request, res: Response) => {
	res.end("API is working!");
});



/**
 * @api {post} /encode
 * @apiName Encode JWT
 * @apiGroup
 * @apiDescription Encode JWT user token.
 *
 *
 * @apiSuccess (200: Success) {String} token JWT token of authenticated user
 * @apiSuccessExample Example Success Response:
 *     HTTP/1.1 200 OK
 *     {"token": "loremipsumdolorsitamet"}
 */
app.post("/encode", (req: Request, res: Response) => {
	// console.log(JSON.stringify(req.body));
	const headingString: string = btoa(JSON.stringify({
		"alg": "HS256",
		"typ": "JWT",
	}));
	const payloadString:string = btoa(JSON.stringify(req.body));

	const hasher: Hmac = crypto.createHmac("sha256", key!);
	const hashedString: string = hasher.update(headingString + "." + payloadString).digest("base64");

	res.send({
		token: headingString + "." + payloadString + "." + hashedString,
	});
});

/**
 * @api {post} /decode
 * @apiName Decode JWT
 * @apiGroup
 * @apiDescription Decode JWT user token.
 *
 *
 * @apiSuccess (200: Success) {String} token JWT token of authenticated user
 * @apiSuccessExample Example Success Response:
 *     HTTP/1.1 200 OK
 *     {"user": "loremipsum", "data": {}}
 */
app.post("/decode", (req: CustomRequest<DecodeRequestModel>, res: Response) => {

	try {
		// console.log(req.body);
		const token: string = req.body.token;
		const splitToken: string[] = token.split(".");

		const headingIndex: number = 0, payloadIndex: number = 1, hashIndex: number = 2;

		const headingString: string = splitToken[headingIndex]!;
		const payloadString: string = splitToken[payloadIndex]!;
		const hashedInput: string = splitToken[hashIndex]!;


		const hasher: Hmac = crypto.createHmac("sha256", key!);
		const hashedString: string = hasher.update(headingString + "." + payloadString).digest("base64");
	
		// console.log(token, splitToken, headingString, payloadString, hashedInput, hashedString);

		if (hashedString === hashedInput) {
			res.send(JSON.parse(atob(payloadString)));
		} else {
			res.send({
				worked: false,
			});
		}
	} catch (e) {
		// there could be a ton of things that could go wrong, from token not existing to the string not being formatted correctly
		console.error(e);
		res.send({
			worked: false,
		});
	}
});

// Throw an error if call is made to the wrong API endpoint
app.use("/", (_: Request, res: Response) => {
	res.status(Constants.NOT_FOUND).end("API endpoint does not exist!");
});

export default app;
