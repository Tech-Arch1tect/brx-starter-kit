import { useForm, Head, Link } from '@inertiajs/react';
import { FormEventHandler } from 'react';
import Layout from '../../components/Layout';
import FlashMessages from '../../components/FlashMessages';

interface LoginProps {
  csrfToken?: string;
  emailVerificationEnabled?: boolean;
  rememberMeEnabled?: boolean;
  rememberMeDays?: number;
}

export default function Login({
  csrfToken,
  emailVerificationEnabled,
  rememberMeEnabled,
  rememberMeDays,
}: LoginProps) {
  const { data, setData, post, processing, errors } = useForm({
    username: '',
    password: '',
    remember_me: false,
  });

  const submit: FormEventHandler = (e) => {
    e.preventDefault();
    post('/auth/login', {
      headers: {
        'X-CSRF-Token': csrfToken || '',
      },
    });
  };

  return (
    <Layout>
      <Head title="Login" />
      <div className="min-h-full flex flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
        </div>

        <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
            <FlashMessages className="mb-4" />

            <form className="space-y-6" onSubmit={submit}>
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                  Username
                </label>
                <div className="mt-1">
                  <input
                    id="username"
                    name="username"
                    type="text"
                    required
                    value={data.username}
                    onChange={(e) => setData('username', e.target.value)}
                    className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  />
                  {errors.username && (
                    <p className="mt-2 text-sm text-red-600">{errors.username}</p>
                  )}
                </div>
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                  Password
                </label>
                <div className="mt-1">
                  <input
                    id="password"
                    name="password"
                    type="password"
                    required
                    value={data.password}
                    onChange={(e) => setData('password', e.target.value)}
                    className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  />
                  {errors.password && (
                    <p className="mt-2 text-sm text-red-600">{errors.password}</p>
                  )}
                </div>
              </div>

              {rememberMeEnabled && (
                <div className="flex items-center">
                  <input
                    id="remember_me"
                    name="remember_me"
                    type="checkbox"
                    checked={data.remember_me}
                    onChange={(e) => setData('remember_me', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="remember_me" className="ml-2 block text-sm text-gray-900">
                    Remember me for {rememberMeDays || 30} days
                  </label>
                </div>
              )}

              <div>
                <button
                  type="submit"
                  disabled={processing}
                  className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {processing ? 'Signing in...' : 'Sign in'}
                </button>
              </div>

              <div className="space-y-2">
                <div className="text-center">
                  <Link
                    href="/auth/password-reset"
                    className="text-sm font-medium text-blue-600 hover:text-blue-500"
                  >
                    Forgot your password?
                  </Link>
                </div>

                {emailVerificationEnabled && (
                  <div className="text-center">
                    <form method="POST" action="/auth/resend-verification" className="inline">
                      <input type="hidden" name="_token" value={csrfToken} />
                      <input
                        type="email"
                        name="email"
                        placeholder="Enter email to resend verification"
                        className="text-xs px-2 py-1 border rounded mr-2 w-48"
                      />
                      <button
                        type="submit"
                        className="text-xs font-medium text-blue-600 hover:text-blue-500 underline"
                      >
                        Resend verification
                      </button>
                    </form>
                  </div>
                )}

                <div className="text-center">
                  <p className="text-sm text-gray-600">
                    Don't have an account?{' '}
                    <Link
                      href="/auth/register"
                      className="font-medium text-blue-600 hover:text-blue-500"
                    >
                      Register here
                    </Link>
                  </p>
                </div>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Layout>
  );
}
