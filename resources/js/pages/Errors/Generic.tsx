import React from 'react';
import { Head, Link } from '@inertiajs/react';

interface GenericErrorProps {
  code?: number;
  message?: string;
}

export default function GenericError({ code = 500, message }: GenericErrorProps) {
  const getErrorTitle = (code: number) => {
    switch (code) {
      case 400:
        return 'Bad Request';
      case 401:
        return 'Unauthorized';
      case 403:
        return 'Forbidden';
      case 404:
        return 'Not Found';
      case 429:
        return 'Too Many Requests';
      case 500:
        return 'Internal Server Error';
      default:
        return 'Error';
    }
  };

  return (
    <>
      <Head title={`${code} - ${getErrorTitle(code)}`} />

      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="text-center">
          <h1 className="text-9xl font-bold text-gray-300 dark:text-gray-600">{code}</h1>
          <h2 className="mt-4 text-2xl font-semibold text-gray-900 dark:text-white">
            {message || getErrorTitle(code)}
          </h2>
          <p className="mt-2 text-gray-600 dark:text-gray-400">Something went wrong.</p>

          <div className="mt-6 space-x-4">
            <Link
              href="/"
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 dark:bg-indigo-700 hover:bg-indigo-700 dark:hover:bg-indigo-600"
            >
              Go Home
            </Link>

            <button
              onClick={() => window.history.back()}
              className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Go Back
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
