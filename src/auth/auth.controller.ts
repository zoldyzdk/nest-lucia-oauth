import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  cookies: string[];
  constructor(private authService: AuthService) { }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async signIn(
    @Req() req: Request,
    @Res({ passthrough: true }) response: Response,
    @Body() signInDto: Record<string, any>,
  ) {
    const cookie = await this.authService.signIn(
      signInDto.username,
      signInDto.password,
    );

    response.setHeader('Set-Cookie', cookie);

    return { message: 'User signed in' };
  }

  @HttpCode(HttpStatus.OK)
  @Post('register')
  async register(
    @Res({ passthrough: true }) response: Response,
    @Body() registerDto: Record<string, any>,
  ) {
    const cookie = await this.authService.register(
      registerDto.username,
      registerDto.password,
    );

    response.setHeader('Set-Cookie', cookie);

    return { message: 'User registered' };
  }

  @HttpCode(HttpStatus.OK)
  @Get('github')
  async github(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const { url, state } = await this.authService.github();
    // this.cookies = [state];
    res.cookie('github_oauth_state', state, {
      path: '/',
      httpOnly: true,
      maxAge: 1000 * 60 * 10,
      sameSite: 'lax',
    });
    res.redirect(url.toString());
  }

  @HttpCode(HttpStatus.OK)
  @Get('github/callback')
  async validateCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    // console.log(this.cookies.find((cookie) => cookie === state));
    const teste = await this.authService.validateCallback(
      code,
      state,
      req,
      res,
    );
  }
}
