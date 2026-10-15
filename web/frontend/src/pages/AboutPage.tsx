import { BookOpen, ExternalLink, GitBranch, ShieldAlert } from 'lucide-react';

const repositoryURL = 'https://github.com/DanielDietz-de/TraceSleuth';
const upstreamURL = 'https://github.com/gocisse/sdwan-triage';

export function AboutPage() {
  const prerelease = __TRACESLEUTH_VERSION__.startsWith('0.');

  return (
    <section className="mx-auto max-w-3xl space-y-6" aria-labelledby="about-title">
      <div className="space-y-3">
        <h2 id="about-title" className="text-3xl font-bold text-slate-900 dark:text-white">
          About TraceSleuth
        </h2>
        <p className="text-slate-700 dark:text-slate-300">
          TraceSleuth is an independent, local-first packet capture analysis project.
          The long-term goal is evidence-backed network fault diagnosis with
          traceable packet references and explicit uncertainty.
        </p>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Build and support</h3>
        <dl className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <dt className="text-sm text-slate-500 dark:text-slate-400">Version</dt>
            <dd className="font-mono font-semibold text-slate-900 dark:text-white">
              {__TRACESLEUTH_VERSION__}
            </dd>
          </div>
          <div>
            <dt className="text-sm text-slate-500 dark:text-slate-400">Release channel</dt>
            <dd className="text-slate-900 dark:text-white">
              {prerelease ? 'Development / prerelease' : 'Versioned release'}
            </dd>
          </div>
        </dl>
        {prerelease && (
          <p role="status" className="mt-4 flex items-start gap-2 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100">
            <ShieldAlert aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
            Pre-1.0 development build: not production-ready. Features and detector
            confidence models are still being validated.
          </p>
        )}
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h3 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white">
          <GitBranch aria-hidden="true" className="h-5 w-5" />
          Upstream provenance and licensing
        </h3>
        <p className="mt-3 text-slate-700 dark:text-slate-300">
          TraceSleuth originated from the MIT-licensed SD-WAN Triage project by Gocisse
          (copyright 2025–2026). TraceSleuth is an independent downstream project;
          no endorsement by the original author or upstream project is implied.
          The original MIT copyright and permission notice remain in the repository.
        </p>
        <ul className="mt-4 space-y-3 text-sm">
          <li>
            <a href={upstreamURL} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-blue-600 underline hover:text-blue-700 dark:text-blue-400">
              Original SD-WAN Triage project <ExternalLink aria-hidden="true" className="h-4 w-4" />
            </a>
          </li>
          <li>
            <a href={`${repositoryURL}/blob/main/UPSTREAM.md`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-blue-600 underline hover:text-blue-700 dark:text-blue-400">
              Exact upstream baseline and attribution <ExternalLink aria-hidden="true" className="h-4 w-4" />
            </a>
          </li>
          <li>
            <a href={`${repositoryURL}/blob/main/LICENSE`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-blue-600 underline hover:text-blue-700 dark:text-blue-400">
              MIT license and copyright notice <ExternalLink aria-hidden="true" className="h-4 w-4" />
            </a>
          </li>
        </ul>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h3 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white">
          <BookOpen aria-hidden="true" className="h-5 w-5" />
          Documentation and limitations
        </h3>
        <p className="mt-2 text-slate-700 dark:text-slate-300">
          Supported behavior, development milestones and unresolved capabilities
          are recorded in the repository roadmap and scope documentation.
        </p>
        <a href={`${repositoryURL}/blob/main/ROADMAP.md`} target="_blank" rel="noopener noreferrer" className="mt-3 inline-flex items-center gap-2 text-sm text-blue-600 underline hover:text-blue-700 dark:text-blue-400">
          Current roadmap and implementation status <ExternalLink aria-hidden="true" className="h-4 w-4" />
        </a>
      </div>
    </section>
  );
}
