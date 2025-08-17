import { FlashMessage as FlashMessageType } from '../types';

interface FlashMessageProps {
  flash: FlashMessageType;
  className?: string;
}

export default function FlashMessage({ flash, className = '' }: FlashMessageProps) {
  const getStyleClasses = (type: FlashMessageType['type']) => {
    switch (type) {
      case 'success':
        return 'text-green-700 bg-green-100 border-green-200';
      case 'error':
        return 'text-red-700 bg-red-100 border-red-200';
      case 'warning':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200';
      case 'info':
        return 'text-blue-700 bg-blue-100 border-blue-200';
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200';
    }
  };

  return (
    <div className={`p-4 text-sm border rounded-lg ${getStyleClasses(flash.type)} ${className}`}>
      {flash.message}
    </div>
  );
}
