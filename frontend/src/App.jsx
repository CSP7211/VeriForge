import React, { useState, useEffect } from 'react'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import FindingsPage from './pages/FindingsPage'
import CompliancePage from './pages/CompliancePage'
import ProjectsPage from './pages/ProjectsPage'
import TeamsPage from './pages/TeamsPage'

const routes = {
  '#/': Dashboard,
  '#/scan': ScanPage,
  '#/findings': FindingsPage,
  '#/compliance': CompliancePage,
  '#/projects': ProjectsPage,
  '#/teams': TeamsPage,
}

function getRouteComponent() {
  const hash = window.location.hash || '#/';
  return routes[hash] || Dashboard;
}

export default function App() {
  const [currentPage, setCurrentPage] = useState(window.location.hash || '#/');

  useEffect(() => {
    const handleHashChange = () => {
      setCurrentPage(window.location.hash || '#/');
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const PageComponent = getRouteComponent();

  return (
    <Layout currentPage={currentPage}>
      <div key={currentPage} className="animate-fade-in">
        <PageComponent />
      </div>
    </Layout>
  );
}
