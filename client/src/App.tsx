import React, { useCallback, useEffect, useState } from 'react';

const API_URL = process.env.REACT_APP_BACKEND_URL!;

function App() {
  const [data, setData] = useState<string>();
  const [token, setToken] = useState<string>();

  const getData = useCallback(async () => {
    if (token) {
      const response = await fetch(API_URL, {
        headers: {
          Authorization: token,
        },
      });
      const { data } = await response.json();
      setData(data);
    }
  }, [token]);

  useEffect(() => {
    if (token) {
      getData();
    }
  }, [token, getData]);

  const updateData = async () => {
    if (token) {
      await fetch(API_URL, {
        method: 'POST',
        body: JSON.stringify({ data }),
        headers: {
          Authorization: token,
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
      });
  
      await getData();
    }
  };

  const verifyData = async () => {
    throw new Error('Not implemented');
  };

  const handleLogin = async () => {
    // Simulate user login (replace with your authentication logic)
    try {
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: 'SamCarter',
          password: 'SamCarter',
        }),
      });

      if (response.ok) {
        const { token } = await response.json();
        setToken(token);
      } else {
        const errorData = await response.json();
        alert(`Login failed: ${errorData.error}`);
      }
    } catch (error) {
      console.error('Error during login:', error);
    }
  };

  if (!token) {
    return <button onClick={handleLogin}>Login</button>;
  }

  return (
    <div
      style={{
        width: '100vw',
        height: '100vh',
        display: 'flex',
        position: 'absolute',
        padding: 0,
        justifyContent: 'center',
        alignItems: 'center',
        flexDirection: 'column',
        gap: '20px',
        fontSize: '30px',
      }}
    >
      <div>Saved Data</div>
      <input style={{ fontSize: '30px' }} type='text' value={data} onChange={(e) => setData(e.target.value)} />

      <div style={{ display: 'flex', gap: '10px' }}>
        <button style={{ fontSize: '20px' }} onClick={updateData}>
          Update Data
        </button>
        <button style={{ fontSize: '20px' }} onClick={verifyData}>
          Verify Data
        </button>
      </div>
    </div>
  );
}

export default App;
