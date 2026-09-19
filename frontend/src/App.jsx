import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Header from './components/Header/Header'
import Landing from './pages/Landing'
import ScanDashboard from './pages/ScanDashboard'
import Results from './pages/Results'
import History from './pages/History'

function App() {
  return (
    <BrowserRouter>
      <div className="bg-grid" />
      <Header />
      <main style={{ flex: 1, position: 'relative', zIndex: 1 }}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/scan/:scanId" element={<ScanDashboard />} />
          <Route path="/results/:scanId" element={<Results />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </main>
    </BrowserRouter>
  )
}

export default App
