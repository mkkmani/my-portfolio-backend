const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const SignUpSchema = {
  name: {
    type: String,
    required: true,
  },

  mobile: {
    type: String,
    required: true,
  },

  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
};

const ProjectSchema = {
  projectName: {
    type: String,
    required: true,
  },

  projectUrl: {
    type: String,
    required: true,
  },

  gitLink: {
    type: String,
    required: true,
  },
  previewImage: {
    type: String,
    required: true,
  },
};

const Admin = new mongoose.model("Admin", SignUpSchema);
const Project = new mongoose.model("Project", ProjectSchema);

const mongoose_uri = process.env.MONGOOSE_URI;
const port = process.env.PORT;

const databaseConnection = async () => {
  try {
    await mongoose.connect(mongoose_uri, { autoCreate: true });
    console.log("database connected successfully");
    app.listen(port || 5008, () => {
      console.log(`app is listening on port ${port || 5008}`);
    });
  } catch (error) {
    console.log("error in database connection", error);
    process.exit(1);
  }
};

//middleware for token authentication
const tokenAuthentication = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return res
      .status(401)
      .json({ error: "Unauthorized: Access token missing" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const validToken = jwt.verify(token, process.env.MY_SECRET_CODE);

    if (validToken) {
      req.details = req.body;
      next();
    } else {
      res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
  } catch (error) {
    // console.error("Error in token authentication:", error.message);
    res.status(403).json({ error: " Error in token authentication" });
  }
};

//end points
//account signup
app.post("/admin/signup", async (req, res) => {
  try {
    const { name, mobile, email, password } = req.body;
    //hashing the password
    const hashedPass = await bcrypt.hash(password, 10);
    //creating new admin instance
    const newAdmin = new Admin({
      name,
      mobile,
      email,
      password: hashedPass,
    });

    await newAdmin.save();

    // Send success response
    res.status(201).json({ message: "Admin created successfully" });
  } catch (error) {
    // error in making request
    console.error("Error in admin signup:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//admin login
app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await Admin.findOne({
      $or: [{ mobile: username }, { email: username }],
    });
    if (user) {
      // Validating the password
      const validPassword = await bcrypt.compare(password, user.password);
      if (validPassword) {
        // Generating token
        const payload = { id: user._id, name: user.name, email: user.email };
        const token = jwt.sign(payload, process.env.MY_SECRET_CODE, {
          expiresIn: "1h",
        });
        res.status(200).json({ jwtToken: token });
      } else {
        res.status(401).json({ error: "Invalid password" });
      }
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    console.error("Error in login", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//adding project
app.post("/project", tokenAuthentication, async (req, res) => {
  const { projectName, projectUrl, gitLink, previewImage } = req.details;

  try {
    const newProject = new Project({
      projectName,
      projectUrl,
      gitLink,
      previewImage,
    });

    await newProject.save();
    res.status(200).json({ message: "project added successfully" });
  } catch (error) {
    res.status(500).json({ error: "error in creating new project" });
  }
});

//remove project from the list
app.delete("/project", tokenAuthentication, async (req, res) => {
  const { projectUrl } = req.details;
  try {
    const project = await Project.findOne({ projectUrl: projectUrl });
    if (project) {
      await Project.findOneAndDelete({ projectUrl: projectUrl });
      res.status(200).send({ message: "Projected removed successfully" });
    } else {
      res.status(401).json({ error: "Project not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

//get all projects
app.get("/projects", async (req, res) => {
  try {
    const projects = await Project.find();
    res.status(200).json({ projectsList: projects });
  } catch (error) {
    res
      .status(500)
      .json({ error: "internal server error in getting projects" });
  }
});

databaseConnection();
