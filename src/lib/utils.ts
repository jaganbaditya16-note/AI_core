import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/** shadcn / 21st.dev component class helper. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
