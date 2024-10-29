import { AuthService } from './auth.service';
export declare class AuthController {
    private authService;
    constructor(authService: AuthService);
    signup(body: {
        email: string;
        password: string;
    }): Promise<{
        token: string;
    }>;
    login(body: {
        email: string;
        password: string;
    }): Promise<{
        token: string;
    }>;
    verifyToken(auth: string): Promise<{
        remainingScrapes: number;
        isValid: boolean;
    }>;
    updateScrapes(auth: string): Promise<{
        remainingScrapes: number;
    }>;
}
