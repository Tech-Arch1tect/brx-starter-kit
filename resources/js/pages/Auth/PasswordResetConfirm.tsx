import { FormEvent, useState } from 'react';
import { Head, useForm, Link } from '@inertiajs/react';
import Layout from '../../components/Layout';

interface Props {
    token: string;
    flash?: string;
    csrfToken?: string;
}

export default function PasswordResetConfirm({ token, flash, csrfToken }: Props) {
    const { data, setData, post, processing, errors } = useForm({
        token: token,
        password: '',
        password_confirm: '',
    });

    const handleSubmit = (e: FormEvent) => {
        e.preventDefault();
        post('/auth/password-reset/confirm', {
            headers: {
                'X-CSRF-Token': csrfToken || '',
            },
        });
    };

    return (
        <Layout>
            <Head title="Reset Password" />
            
            <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
                <div className="max-w-md w-full space-y-8">
                    <div>
                        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
                            Choose a new password
                        </h2>
                        <p className="mt-2 text-center text-sm text-gray-600">
                            Enter your new password below.
                        </p>
                    </div>
                    
                    <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                        {flash && (
                            <div className="rounded-md bg-red-50 p-4">
                                <div className="text-sm text-red-700">{flash}</div>
                            </div>
                        )}
                        
                        <input type="hidden" name="token" value={data.token} />
                        
                        <div className="space-y-4">
                            <div>
                                <label htmlFor="password" className="sr-only">
                                    New Password
                                </label>
                                <input
                                    id="password"
                                    name="password"
                                    type="password"
                                    autoComplete="new-password"
                                    required
                                    className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                                    placeholder="New password"
                                    value={data.password}
                                    onChange={(e) => setData('password', e.target.value)}
                                />
                                {errors.password && (
                                    <p className="mt-1 text-sm text-red-600">{errors.password}</p>
                                )}
                            </div>
                            
                            <div>
                                <label htmlFor="password_confirm" className="sr-only">
                                    Confirm New Password
                                </label>
                                <input
                                    id="password_confirm"
                                    name="password_confirm"
                                    type="password"
                                    autoComplete="new-password"
                                    required
                                    className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                                    placeholder="Confirm new password"
                                    value={data.password_confirm}
                                    onChange={(e) => setData('password_confirm', e.target.value)}
                                />
                                {errors.password_confirm && (
                                    <p className="mt-1 text-sm text-red-600">{errors.password_confirm}</p>
                                )}
                            </div>
                        </div>

                        <div>
                            <button
                                type="submit"
                                disabled={processing}
                                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                            >
                                {processing ? 'Resetting...' : 'Reset password'}
                            </button>
                        </div>

                        <div className="text-center">
                            <Link
                                href="/auth/login"
                                className="font-medium text-indigo-600 hover:text-indigo-500"
                            >
                                Back to login
                            </Link>
                        </div>
                    </form>
                </div>
            </div>
        </Layout>
    );
}