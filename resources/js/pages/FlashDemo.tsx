import React from 'react'
import { Head, usePage, router } from '@inertiajs/react'
import { PageProps as InertiaPageProps } from '@inertiajs/core'

interface FlashDemoProps {
    title: string
    description: string
}

interface PageProps extends InertiaPageProps {
    errors?: Record<string, string>
}

export default function FlashDemo({ title, description }: FlashDemoProps) {
    const { errors } = usePage<PageProps>().props

    const handleFlashAction = (type: string) => {
        router.post(`/flash/${type}`, {}, {
            preserveState: false,
            preserveScroll: false,
        })
    }

    return (
        <div className="min-h-screen bg-gray-50">
            <Head title={title} />
            
            <div className="container mx-auto px-6 py-8">
                <div className="max-w-4xl mx-auto">
                    {/* Header */}
                    <div className="text-center mb-8">
                        <h1 className="text-4xl font-bold text-gray-900 mb-2">{title}</h1>
                        <p className="text-gray-600 text-lg">{description}</p>
                    </div>

                    {/* Flash Messages Display */}
                    <div className="mb-8 space-y-4">
                        {errors?.flash && (
                            <div className="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded-lg">
                                <div className="flex items-center">
                                    <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                                    </svg>
                                    <strong>Flash:</strong> <span className="ml-1">{errors.flash}</span>
                                </div>
                            </div>
                        )}

                        {errors?.success && (
                            <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded-lg">
                                <div className="flex items-center">
                                    <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                    </svg>
                                    <strong>Success:</strong> <span className="ml-1">{errors.success}</span>
                                </div>
                            </div>
                        )}

                        {errors?.warning && (
                            <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded-lg">
                                <div className="flex items-center">
                                    <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                                    </svg>
                                    <strong>Warning:</strong> <span className="ml-1">{errors.warning}</span>
                                </div>
                            </div>
                        )}

                        {errors && Object.keys(errors).filter(key => !['flash', 'success', 'warning'].includes(key)).length > 0 && (
                            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg">
                                <div className="flex items-start">
                                    <svg className="w-5 h-5 mr-2 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                                    </svg>
                                    <div>
                                        <strong>Validation Errors:</strong>
                                        <ul className="mt-2 list-disc list-inside">
                                            {Object.entries(errors).filter(([key]) => !['flash', 'success', 'warning'].includes(key)).map(([field, message]) => (
                                                <li key={field}>
                                                    <strong className="capitalize">{field}:</strong> {message}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Action Buttons */}
                    <div className="bg-white rounded-lg shadow-lg p-8">
                        <h2 className="text-2xl font-semibold mb-6 text-center">Test Flash Messages</h2>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <button
                                onClick={() => handleFlashAction('basic')}
                                className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
                            >
                                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                                </svg>
                                Basic Flash
                            </button>
                            <button
                                onClick={() => handleFlashAction('success')}
                                className="bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
                            >
                                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                </svg>
                                Success Flash
                            </button>
                            <button
                                onClick={() => handleFlashAction('error')}
                                className="bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
                            >
                                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                                </svg>
                                Error Flash
                            </button>
                            <button
                                onClick={() => handleFlashAction('warning')}
                                className="bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
                            >
                                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                                </svg>
                                Warning Flash
                            </button>
                        </div>
                    </div>

                    {/* Documentation */}
                    <div className="mt-8 bg-white rounded-lg shadow-lg p-8">
                        <h2 className="text-2xl font-semibold mb-6">How Flash Messages Work</h2>
                        <div className="space-y-4 text-gray-700">
                            <p className="text-lg">
                                This demo shows seamless integration between brx (Go backend) and Inertia.js (React frontend):
                            </p>
                            <ol className="list-decimal list-inside space-y-3 ml-4">
                                <li>Flash messages are stored server-side using SCS session management</li>
                                <li>The Inertia middleware automatically shares flash data as props</li>
                                <li>React components receive flash messages via <code className="bg-gray-100 px-2 py-1 rounded">usePage().props</code></li>
                                <li>Messages are automatically cleared after being displayed (one-time use)</li>
                            </ol>
                            <div className="bg-gray-50 p-6 rounded-lg mt-6">
                                <h3 className="font-semibold mb-3 text-lg">Flash Message Integration:</h3>
                                <div className="grid grid-cols-1 gap-4 text-sm">
                                    <div>
                                        <code className="bg-white px-2 py-1 rounded border">errors.flash</code>
                                        <p className="text-gray-600 mt-1">Basic flash messages via Gonertia validation errors</p>
                                    </div>
                                    <div>
                                        <code className="bg-white px-2 py-1 rounded border">errors.success</code>
                                        <p className="text-gray-600 mt-1">Success notifications</p>
                                    </div>
                                    <div>
                                        <code className="bg-white px-2 py-1 rounded border">errors.warning</code>
                                        <p className="text-gray-600 mt-1">Warning messages</p>
                                    </div>
                                    <div>
                                        <code className="bg-white px-2 py-1 rounded border">errors.*</code>
                                        <p className="text-gray-600 mt-1">Form validation errors</p>
                                    </div>
                                </div>
                                <p className="text-xs text-gray-500 mt-4">
                                    Flash messages are handled by Gonertia's built-in FlashProvider with SCS session storage
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}