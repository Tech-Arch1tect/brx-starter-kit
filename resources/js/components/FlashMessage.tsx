import { FlashMessage as FlashMessageType } from '../types';

interface FlashMessageProps {
  flash: FlashMessageType;
  className?: string;
}

export default function FlashMessage({ flash, className = '' }: FlashMessageProps) {
  const getStyleClasses = (type: FlashMessageType['type']) => {
    switch (type) {
      case 'success':
        return 'text-green-700 dark:text-green-300 bg-green-100 dark:bg-green-900/20 border-green-200 dark:border-green-800';
      case 'error':
        return 'text-red-700 dark:text-red-300 bg-red-100 dark:bg-red-900/20 border-red-200 dark:border-red-800';
      case 'warning':
        return 'text-yellow-700 dark:text-yellow-300 bg-yellow-100 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
      case 'info':
        return 'text-blue-700 dark:text-blue-300 bg-blue-100 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800';
      default:
        return 'text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-900/20 border-gray-200 dark:border-gray-700';
    }
  };

  return (
    <div className={`p-4 text-sm border rounded-lg ${getStyleClasses(flash.type)} ${className}`}>
      {flash.message}
    </div>
  );
}
