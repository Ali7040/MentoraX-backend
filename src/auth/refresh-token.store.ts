import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

interface RefreshToken{
    userId:number,
    tokenHash:string,
    isRevoke:boolean,
    expiresAt: Date;
}


@Injectable()
export class RefreshTokenStore{
    private tokens:RefreshToken[] = []

    async save(userId:number, token:string){
        const hash = await bcrypt.hash(token, 10)
        this.tokens.push({
            userId,
            tokenHash:token,
            isRevoke:false,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        })
    }

    async findValid(userId:number, token:string){
        for(const t of this.tokens){
            if(t.userId === userId && !t.isRevoke){
                const match = await bcrypt.compare(token , t.tokenHash)
                if(match) return t;
            }
        }
        return null;
    }


    revoke(token: RefreshToken){
        token.isRevoke = true;
    }

    revokeAll(userId:number){
        this.tokens.forEach(t =>{
            if(t.userId === userId) t.isRevoke = true;
        })
    }

}