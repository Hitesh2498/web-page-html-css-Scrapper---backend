import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User } from './schemas/user.schema';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signup(email: string, password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new this.userModel({
      email,
      password: hashedPassword,
    });
    await user.save();
    return this.generateToken(user);
  }

  async login(email: string, password: string) {
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException();
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException();
    }

    return this.generateToken(user);
  }

  private generateToken(user: User) {
    return {
      token: this.jwtService.sign({ userId: user._id }),
    };
  }

  async verifyToken(token: string) {
    try {
      const decoded = this.jwtService.verify(token);
      const user = await this.userModel.findById(decoded.userId);
      if (!user) throw new UnauthorizedException();
      return {
        remainingScrapes: user.scrapesUsed,
        isValid: true,
      };
    } catch {
      throw new UnauthorizedException();
    }
  }

  async updateScrapes(token: string) {
    const decoded = this.jwtService.verify(token);
    const user = await this.userModel.findById(decoded.userId);
    if (!user) throw new UnauthorizedException();

    const now = new Date();
    const lastReset = new Date(user.lastScrapeReset);
    if (
      now.getDate() !== lastReset.getDate() ||
      now.getMonth() !== lastReset.getMonth() ||
      now.getFullYear() !== lastReset.getFullYear()
    ) {
      user.scrapesUsed = 0;
      user.lastScrapeReset = now;
    }

    user.scrapesUsed += 1;
    await user.save();

    return {
      remainingScrapes: 50 - user.scrapesUsed,
    };
  }
}
