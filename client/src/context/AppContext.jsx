import axios from "axios";
import { createContext, useEffect, useState } from "react";
import { toast } from "react-toastify";

export const AppContent = createContext()

export const AppContextProvider = (props) =>{

    axios.defaults.withCredentials = true

    const backendUrl = import.meta.env.VITE_BACKEND_URL
    const [isLoggedin, setIsLoggedin] = useState(false)
    const [userData, setUserData] = useState(false)

    const getAuthState = async () => {
        try {
            console.log('Checking auth state...')
            const {data} = await axios.get(backendUrl + '/api/auth/is-auth')
            console.log('Auth state response:', data)
            
            if(data.success || data.sucess){  // Handle both spellings temporarily
                console.log('User is authenticated, setting logged in state')
                setIsLoggedin(true)
                getUserData()
            } else {
                console.log('User is not authenticated')
                setIsLoggedin(false)
                setUserData(false)
            }
        } catch (error) {
            console.error('Auth check error:', error)
            setIsLoggedin(false)
            setUserData(false)
            // Don't show toast error for auth check failures
        }
    }

    const getUserData = async () => {
        try {
            const {data} = await axios.get(backendUrl + '/api/user/data')
            console.log(data)
            data.success ? setUserData(data.userDate) : toast.error(data.message)
        } catch (error) {
            toast.error(error.message)
        }
    }

    useEffect(()=>{
        getAuthState()
    },[])

    const value = {
        backendUrl,
        isLoggedin,setIsLoggedin,
        userData,setUserData,
        getUserData,
    }

    return (
        <AppContent.Provider value={value}>
            {props.children}
        </AppContent.Provider>
    )
}