import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ collection: 'USERS_scrapper' })
export class User extends Document {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: 0 })
  scrapesUsed: number;

  @Prop({ default: Date.now })
  lastScrapeReset: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
