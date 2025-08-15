import React from 'react';
import { Head, Link } from '@inertiajs/react';

interface GenericErrorProps {
    code?: number;
    message?: string;
}

export default function GenericError({ code = 500, message }: GenericErrorProps) {
    const getErrorTitle = (code: number) => {
        switch (code) {
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            default: return "Error";
        }
    };

    return (
        <>
            <Head title={`${code} - ${getErrorTitle(code)}`} />
            
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center">
                    <h1 className="text-9xl font-bold text-gray-300">{code}</h1>
                    <h2 className="mt-4 text-2xl font-semibold text-gray-900">
                        {message || getErrorTitle(code)}
                    </h2>
                    <p className="mt-2 text-gray-600">Something went wrong.</p>
                    
                    <div className="mt-6 space-x-4">
                        <Link
                            href="/"
                            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700"
                        >
                            Go Home
                        </Link>
                        
                        <button
                            onClick={() => window.history.back()}
                            className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                        >
                            Go Back
                        </button>
                    </div>
                </div>
            </div>
        </>
    );
}