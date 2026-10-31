import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
const cn = (...values: unknown[]) => twMerge(clsx(values));
const styles = cva("button", { variants: { variant: { primary: "primary", quiet: "quiet", outline: "" }, size: { default: "", sm: "small" } }, defaultVariants: { variant: "outline", size: "default" } });
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof styles> {}
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(({ className, variant, size, ...props }, ref) => <button ref={ref} className={cn(styles({ variant, size }), className)} {...props} />);
Button.displayName = "Button";
