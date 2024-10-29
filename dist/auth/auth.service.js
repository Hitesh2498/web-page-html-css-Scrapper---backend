"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const mongoose_1 = require("@nestjs/mongoose");
const mongoose_2 = require("mongoose");
const jwt_1 = require("@nestjs/jwt");
const bcrypt = require("bcrypt");
const user_schema_1 = require("./schemas/user.schema");
let AuthService = class AuthService {
    constructor(userModel, jwtService) {
        this.userModel = userModel;
        this.jwtService = jwtService;
    }
    async signup(email, password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new this.userModel({
            email,
            password: hashedPassword,
        });
        await user.save();
        return this.generateToken(user);
    }
    async login(email, password) {
        const user = await this.userModel.findOne({ email });
        if (!user) {
            throw new common_1.UnauthorizedException();
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new common_1.UnauthorizedException();
        }
        return this.generateToken(user);
    }
    generateToken(user) {
        return {
            token: this.jwtService.sign({ userId: user._id }),
        };
    }
    async verifyToken(token) {
        try {
            const decoded = this.jwtService.verify(token);
            const user = await this.userModel.findById(decoded.userId);
            if (!user)
                throw new common_1.UnauthorizedException();
            return {
                remainingScrapes: user.scrapesUsed,
                isValid: true,
            };
        }
        catch {
            throw new common_1.UnauthorizedException();
        }
    }
    async updateScrapes(token) {
        const decoded = this.jwtService.verify(token);
        const user = await this.userModel.findById(decoded.userId);
        if (!user)
            throw new common_1.UnauthorizedException();
        const now = new Date();
        const lastReset = new Date(user.lastScrapeReset);
        if (now.getDate() !== lastReset.getDate() ||
            now.getMonth() !== lastReset.getMonth() ||
            now.getFullYear() !== lastReset.getFullYear()) {
            user.scrapesUsed = 0;
            user.lastScrapeReset = now;
        }
        user.scrapesUsed += 1;
        await user.save();
        return {
            remainingScrapes: 50 - user.scrapesUsed,
        };
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_1.InjectModel)(user_schema_1.User.name)),
    __metadata("design:paramtypes", [mongoose_2.Model,
        jwt_1.JwtService])
], AuthService);
//# sourceMappingURL=auth.service.js.map