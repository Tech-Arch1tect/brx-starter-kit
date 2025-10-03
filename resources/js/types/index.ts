export interface FlashMessage {
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
}

export interface Role {
  id: number;
  name: string;
  description: string;
}

export interface User {
  ID: number;
  username: string;
  email: string;
  CreatedAt: string;
  UpdatedAt: string;
  roles?: Role[];
}
