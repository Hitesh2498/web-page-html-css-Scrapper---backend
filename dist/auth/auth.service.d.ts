import { Model } from "mongoose";
import { JwtService } from "@nestjs/jwt";
import { User } from "./schemas/user.schema";
export declare class AuthService {
    private userModel;
    private jwtService;
    constructor(userModel: Model<User>, jwtService: JwtService);
    signup(email: string, password: string): Promise<{
        token: string;
    }>;
    login(email: string, password: string): Promise<{
        token: string;
    }>;
    private generateToken;
    verifyToken(token: string): Promise<{
        remainingScrapes: number;
        isValid: boolean;
    }>;
    private checkAndResetScrapes;
    private shouldResetScrapes;
    updateScrapes(token: string): Promise<{
        remainingScrapes: number;
    }>;
}
