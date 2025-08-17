import { Head, useForm } from '@inertiajs/react';
import Layout from '../../components/Layout';
import { FlashMessage } from '../../types';

interface Props {
  title: string;
  flash?: FlashMessage;
  csrfToken?: string;
}

interface FormData {
  code: string;
}

export default function TOTPVerify({ title, flash, csrfToken }: Props) {
  const { data, setData, post, processing, errors } = useForm<FormData>({
    code: '',
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    post('/auth/totp/verify', {
      headers: {
        'X-CSRF-Token': csrfToken || '',
      },
    });
  };

  return (
    <Layout>
      <Head title={title} />

      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div>
            <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
              Two-Factor Authentication
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600">
              Enter the 6-digit code from your authenticator app
            </p>
          </div>

          {flash && (
            <div
              className={`px-4 py-3 rounded ${
                flash.type === 'success'
                  ? 'text-green-700 bg-green-50 border border-green-200'
                  : flash.type === 'error'
                    ? 'text-red-700 bg-red-50 border border-red-200'
                    : flash.type === 'warning'
                      ? 'text-yellow-700 bg-yellow-50 border border-yellow-200'
                      : 'text-blue-700 bg-blue-50 border border-blue-200'
              }`}
            >
              {flash.message}
            </div>
          )}

          <form className="mt-8 space-y-6" onSubmit={submit}>
            <div>
              <label htmlFor="code" className="sr-only">
                Authentication Code
              </label>
              <input
                id="code"
                name="code"
                type="text"
                value={data.code}
                onChange={(e) => setData('code', e.target.value)}
                className="appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm text-center text-2xl tracking-widest"
                placeholder="123456"
                maxLength={6}
                pattern="[0-9]{6}"
                autoComplete="one-time-code"
                required
              />
              {errors.code && <div className="mt-2 text-red-600 text-sm">{errors.code}</div>}
            </div>

            <div>
              <button
                type="submit"
                disabled={processing}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
              >
                {processing ? 'Verifying...' : 'Verify Code'}
              </button>
            </div>

            <div className="text-center">
              <p className="text-sm text-gray-600">
                Having trouble? Contact support for assistance.
              </p>
            </div>
          </form>
        </div>
      </div>
    </Layout>
  );
}
