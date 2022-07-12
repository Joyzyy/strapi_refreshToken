'use strict';

const crypto = require('crypto');
const _ = require('lodash');
const utils = require('@strapi/utils');
const { getService } = require('@strapi/plugin-users-permissions/server/utils');
const {
  validateCallbackBody,
  validateRegisterBody,
  validateSendEmailConfirmationBody,
  validateForgotPasswordBody,
  validateResetPasswordBody,
  validateEmailConfirmationBody,
} = require('@strapi/plugin-users-permissions/server/controllers/validation/auth');


const { getAbsoluteAdminUrl, getAbsoluteServerUrl, sanitize } = utils;
const { ApplicationError, ValidationError } = utils.errors;

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel('plugin::users-permissions.user');

  return sanitize.contentAPI.output(user, userSchema, { auth });
};

module.exports = (plugin) => {
	plugin.controllers.auth.refreshToken = async(ctx) => {
		if (ctx.request && ctx.request.header && !ctx.request.header.authorization) {
			const token = ctx.cookies.get('???');

			// if we don't have a token, we send a 400 error, as the client should send a token, meaning that the cookie has either been tampered with or the user has not logged in
			if (!token) {
				return ctx.badRequest(400, 'No refresh token provided.');
			}

			// check if the refreshToken is still valid (not expired), if not, we will return a new jwt token for the server (JWT NEEDS TO ME STORED IN MEMORY (variable))
			const checkToken = await strapi.plugins['users-permissions'].services.jwt.verify(token).then((decoded) => {
				if (ctx.cookies.get('isInvalid') && ctx.cookies.get('isInvalid') === 'true')
					return { response_status: ctx.badRequest(400, 'Invalid token.') };
				
				/*
				ctx.cookies.set('???', token, {
					httpOnly: true,
					sameSite: 'Lax',
					maxAge: 1000 * 60 * 60 * 24 * 14,
				}); */

				return { response_status: strapi.plugins['users-permissions'].services.jwt.issue({ id: decoded.id }) };
			}).catch((err) => {
				return { response_status: ctx.badRequest(400, err.message) };
			});

			return { token: checkToken.response_status };
		}
		
		return ctx.badRequest(400, 'No refresh token provided.');
	}

	plugin.routes['content-api'].routes.push({
		method: "GET",
		path: '/auth/refreshToken',
		handler: 'auth.refreshToken',
		config: {
			prefix: ''
		}
	});
	
	plugin.controllers.auth.logout = async(ctx) => {
		// if we have a request, we check for the authorization header (Bearer `our jwt`)
		if (ctx.request && ctx.request.header && ctx.request.header.authorization) {
			// since we can't modify httpOnly cookies on the client side, we need to remove the cookie.
			ctx.cookies.set('???');
			ctx.cookies.set('???.sig');
			// redirect to the index page
			return ctx.redirect('http://localhost:3000');
		}
	}
	
	plugin.routes['content-api'].routes.push({
		method: "POST",
		path: '/auth/logout',
		handler: 'auth.logout',
		config: {
			prefix: ''
		}
	});

	// override the default callback function
	plugin.controllers.auth.callback = async(ctx) => {
		const provider = ctx.params.provider || 'local';
		const params = ctx.request.body;
	
		const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
		const grantSettings = await store.get({ key: 'grant' });
	
		const grantProvider = provider === 'local' ? 'email' : provider;
	
		if (!_.get(grantSettings, [grantProvider, 'enabled'])) {
		  throw new ApplicationError('This provider is disabled');
		}
	
		if (provider === 'local') {
		  await validateCallbackBody(params);
	
		  const { identifier } = params;
	
		  // Check if the user exists.
		  const user = await strapi.query('plugin::users-permissions.user').findOne({
			where: {
			  provider,
			  $or: [{ email: identifier.toLowerCase() }, { username: identifier }],
			},
		  });
	
		  if (!user) {
			throw new ValidationError('Invalid identifier or password');
		  }
	
		  if (!user.password) {
			throw new ValidationError('Invalid identifier or password');
		  }
	
		  const validPassword = await getService('user').validatePassword(
			params.password,
			user.password
		  );
	
		  if (!validPassword) {
			throw new ValidationError('Invalid identifier or password');
		  }
	
		  const advancedSettings = await store.get({ key: 'advanced' });
		  const requiresConfirmation = _.get(advancedSettings, 'email_confirmation');
	
		  if (requiresConfirmation && user.confirmed !== true) {
			throw new ApplicationError('Your account email is not confirmed');
		  }
	
		  if (user.blocked === true) {
			throw new ApplicationError('Your account has been blocked by an administrator');
		  }

		  // if the credentials are valid, we can issue a httpOnly cookie to the client.
		  ctx.cookies.set('???', getService('jwt').issue({id: user.id}), {
			httpOnly: true,
			sameSite: 'lax',
			maxAge: 1000 * 60 * 60 * 24 * 14,
		  });

		  return ctx.send({
			//just for debugging: cookie: ctx.cookies.get('???') ? ctx.cookies.get('???') : '',
			jwt: getService('jwt').issue({ id: user.id }),
			user: await sanitizeUser(user, ctx),
		  });
		}
	
		// Connect the user with the third-party provider.
		try {
		  const user = await getService('providers').connect(provider, ctx.query);
	
		  return ctx.send({
			jwt: getService('jwt').issue({ id: user.id }),
			user: await sanitizeUser(user, ctx),
		  });
		} catch (error) {
		  throw new ApplicationError(error.message);
		}
	}

	// not really necessary, but I'm leaving it in for now
	plugin.routes['content-api'].routes.unshift({
		method: 'POST',
		path: '/auth/local',
		handler: 'auth.callback',
		config: {
			prefix: ''
		}
	});

	// override the default callback function
	plugin.controllers.auth.register = async(ctx) => {
		const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });

		const settings = await pluginStore.get({ key: 'advanced' });
	
		if (!settings.allow_register) {
		  throw new ApplicationError('Register action is currently disabled');
		}
	
		const params = {
		  ..._.omit(ctx.request.body, [
			'confirmed',
			'blocked',
			'confirmationToken',
			'resetPasswordToken',
			'provider',
		  ]),
		  provider: 'local',
		};
	
		await validateRegisterBody(params);
	
		const role = await strapi
		  .query('plugin::users-permissions.role')
		  .findOne({ where: { type: settings.default_role } });
	
		if (!role) {
		  throw new ApplicationError('Impossible to find the default role');
		}
	
		const { email, username, provider } = params;
	
		const identifierFilter = {
		  $or: [
			{ email: email.toLowerCase() },
			{ username: email.toLowerCase() },
			{ username },
			{ email: username },
		  ],
		};
	
		const conflictingUserCount = await strapi.query('plugin::users-permissions.user').count({
		  where: { ...identifierFilter, provider },
		});
	
		if (conflictingUserCount > 0) {
		  throw new ApplicationError('Email or Username are already taken');
		}
	
		if (settings.unique_email) {
		  const conflictingUserCount = await strapi.query('plugin::users-permissions.user').count({
			where: { ...identifierFilter },
		  });
	
		  if (conflictingUserCount > 0) {
			throw new ApplicationError('Email or Username are already taken');
		  }
		}
	
		let newUser = {
		  ...params,
		  role: role.id,
		  email: email.toLowerCase(),
		  username,
		  confirmed: !settings.email_confirmation,
		};
	
		const user = await getService('user').add(newUser);
	
		const sanitizedUser = await sanitizeUser(user, ctx);
	
		if (settings.email_confirmation) {
		  try {
			await getService('user').sendConfirmationEmail(sanitizedUser);
		  } catch (err) {
			throw new ApplicationError(err.message);
		  }
	
		  return ctx.send({ user: sanitizedUser });
		}
	
		const jwt = getService('jwt').issue(_.pick(user, ['id']));
		
		ctx.cookies.set('???', getService('jwt').issue(_.pick(user, ['id'])), {
		  	httpOnly: true,
		   	sameSite: 'lax',
			maxAge: 1000 * 60 * 60 * 24 * 14,
		});

		return ctx.send({
		  jwt,
		  user: sanitizedUser,
		});
	}

	return plugin;
};
