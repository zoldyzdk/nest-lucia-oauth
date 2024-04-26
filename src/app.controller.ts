import { Controller, Get, Res } from '@nestjs/common';
import { AppService } from './app.service';
import { Response } from 'express';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(@Res({ passthrough: true }) res: Response): string {
    res.cookie('teste45', 'aiksdfkasl', {
      path: '/',
      httpOnly: true,
      maxAge: 1000 * 60 * 10,
      // sameSite: 'lax',
    });
    return this.appService.getHello();
  }
}
