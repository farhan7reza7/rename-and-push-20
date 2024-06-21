const { SSMClient, GetParameterCommand } = require("@aws-sdk/client-ssm");

async function getParameter(parameterName) {
  const ssmClient = new SSMClient({ region: "ap-northeast-3" }); // Replace with your desired region

  try {
    const command = new GetParameterCommand({
      Name: parameterName,
      WithDecryption: true,
    });
    const response = await ssmClient.send(command);
    return response.Parameter.Value;
  } catch (error) {
    console.error("Error retrieving parameter:", parameterName);
    //throw error; // Or handle the error gracefully in your application
  }
}

module.exports = { getParameter };
