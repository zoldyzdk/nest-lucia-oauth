// import { createClient } from '@libsql/client';
// import { PrismaAdapter } from '@lucia-auth/adapter-prisma';
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class AuthService {
  private client = new PrismaClient();

  private async insertUser(id, login, githubId) {
    this.client.user.create({
      data: {
        id: id,
        username: login,
        github_id: Number(githubId),
        passwordHash: '12345',
      },
    });
  }

  private async getLucia() {
    const { PrismaAdapter } = await import('@lucia-auth/adapter-prisma');
    const { Lucia } = await import('lucia');

    const adapter = new PrismaAdapter(this.client.session, this.client.user);
    return new Lucia<Record<never, never>, { username: string }>(adapter, {
      sessionCookie: {
        attributes: {
          secure: process.env.NODE_ENV === 'production',
        },
      },
      getUserAttributes: (attributes: {
        username: string;
        github_id: number;
      }) => {
        return {
          username: attributes.username,
          githubId: attributes.github_id,
        };
      },
    });
  }

  private async hashPassword(password: string) {
    const { Argon2id } = await import('oslo/password');
    const passwordHash = await new Argon2id().hash(password);
    return passwordHash;
  }

  private async verifyHash(password: string, hash: string) {
    const { Argon2id } = await import('oslo/password');
    return await new Argon2id().verify(hash, password);
  }

  private async generateId() {
    const { generateId } = await import('lucia');
    return generateId(15);
  }

  private async getGithubProvider() {
    const { GitHub } = await import('arctic');
    const github = new GitHub(
      process.env.GITHUB_CLIENT_ID!,
      process.env.GITHUB_CLIENT_SECRET!,
    );

    return github;
  }

  async signIn(username: string, pass: string): Promise<string> {
    const lucia = await this.getLucia();

    const user = await this.client.user.findUnique({
      where: {
        username,
      },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    const hashVerified = await this.verifyHash(pass, user.passwordHash);
    if (!hashVerified) {
      throw new UnauthorizedException();
    }

    const session = await lucia.createSession(user.id, {});
    return lucia.createSessionCookie(session.id).serialize();
  }

  async register(username: string, pass: string): Promise<string> {
    const user = await this.client.user.findUnique({
      where: {
        username,
      },
    });

    if (user) {
      throw new BadRequestException();
    }

    const userId = await this.generateId();
    const passwordHash = await this.hashPassword(pass);

    const newUser = await this.client.user.create({
      data: {
        id: userId,
        username,
        github_id: 123,
        passwordHash,
      },
    });

    const lucia = await this.getLucia();
    const session = await lucia.createSession(newUser.id, {});
    return lucia.createSessionCookie(session.id).serialize();
  }

  async github(): Promise<{ url: URL; state: string }> {
    const { GitHub, generateState } = await import('arctic');
    // const github = new GitHub(
    //   process.env.GITHUB_CLIENT_ID!,
    //   process.env.GITHUB_CLIENT_SECRET!,
    // );
    const github = await this.getGithubProvider();
    const state = generateState();
    const url = await github.createAuthorizationURL(state);

    return { url, state };
  }

  async validateCallback(
    code: string,
    state: string,
    req: Request,
    res: Response,
  ) {
    // const lucia = await this.getLucia();
    const github = await this.getGithubProvider();
    const { OAuth2RequestError } = await import('arctic');

    const storedState = req.cookies['github_oauth_state'];
    if (!code || !state || !storedState || state !== storedState) {
      return new Response(null, {
        status: 400,
      });
    }

    try {
      const tokens = await github.validateAuthorizationCode(code);
      console.log(tokens);
      const githubUserResponse = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${tokens.accessToken}`,
        },
      });
      const githubUser: { id: string; login: string } =
        await githubUserResponse.json();

      const existingUser = await this.client.user.findFirst({
        where: {
          github_id: Number(githubUser.id),
        },
      });

      if (existingUser) {
        const lucia = await this.getLucia();
        const session = await lucia.createSession(existingUser.id, {});
        const sessionCookie = lucia.createSessionCookie(session.id);
        return {
          cookieName: sessionCookie.name,
          cookieValue: sessionCookie.value,
          cookieAttributes: sessionCookie.attributes,
        };
      }

      const { generateIdFromEntropySize } = await import('lucia');
      const userId = generateIdFromEntropySize(10);
      // await this.insertUser(userId, githubUser.login, githubUser.id);
      const newUser = await this.client.user.create({
        data: {
          id: userId,
          username: githubUser.login,
          github_id: Number(githubUser.id),
          passwordHash: '12345',
        },
      });
      const lucia = await this.getLucia();
      const session = await lucia.createSession(newUser.id, {});
      const sessionCookie = lucia.createSessionCookie(session.id);
      return {
        cookieName: sessionCookie.name,
        cookieValue: sessionCookie.value,
        cookieAttributes: sessionCookie.attributes,
      };
    } catch (err) {
      if (err instanceof OAuth2RequestError) {
        return new Response(null, {
          status: 400,
          statusText: 'Deu erro no try',
        });
      }

      console.log(err);
    }
  }
}
