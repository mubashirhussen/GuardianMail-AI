import React, { useState } from 'react';
import { Lock, Eye, EyeOff } from 'lucide-react';

interface PasswordFieldProps {
  id?: string;
  name?: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  label?: string;
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  autoComplete?: string;
  className?: string;
}

export const PasswordField: React.FC<PasswordFieldProps> = ({
  id = 'password',
  name = 'password',
  value,
  onChange,
  label = 'Password',
  placeholder = '••••••••••••',
  required = true,
  disabled = false,
  autoComplete = 'current-password',
  className = ''
}) => {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <div className={`space-y-1.5 ${className}`}>
      {label && (
        <label htmlFor={id} className="block text-xs font-semibold text-slate-300">
          {label}
        </label>
      )}
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
          <Lock className="h-4 w-4" />
        </div>
        <input
          id={id}
          name={name}
          type={showPassword ? 'text' : 'password'}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          required={required}
          disabled={disabled}
          autoComplete={autoComplete}
          className="w-full pl-10 pr-10 py-2.5 bg-[#091124] border border-[#1b2b4d] rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all disabled:opacity-50"
        />
        <button
          type="button"
          onClick={() => setShowPassword(!showPassword)}
          tabIndex={-1}
          aria-label={showPassword ? 'Hide password' : 'Show password'}
          className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200 transition-colors"
        >
          {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    </div>
  );
};
