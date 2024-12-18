import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        if (!token) { 
            return res.status(401).json({ msg: "Please login to access this route" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRETE);
        if (!decoded) {
            return res.status(401).json({ msg: "Please login to access this route" });
        }

        const user = await User.findById(decoded.userId).select("-password");
        if (!user) {
            return res.status(404).json({ msg: "Please login to access this route" });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: "Server Error" });
    } 
}