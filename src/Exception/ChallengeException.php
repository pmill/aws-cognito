<?php
namespace pmill\AwsCognito\Exception;

class ChallengeException extends \Exception
{
    /**
     * @var string
     */
    protected $challengeName;

    /**
     * @var array
     */
    protected $challengeParameters = [];

    /**
     * @var string
     */
    protected $session;

    /**
     * @var array
     */
    protected $response;

    /**
     * @param array $response
     * @return ChallengeException
     */
    public static function createFromAuthenticateResponse(array $response)
    {
        $challengeException = new ChallengeException();
        $challengeException->setResponse($response);
        $challengeException->setChallengeName($response['ChallengeName']);
        $challengeException->setSession($response['Session']);

        if (isset($response['ChallengeParameters'])) {
            $challengeException->setChallengeParameters($response['ChallengeParameters']);
        }

        return $challengeException;
    }

    /**
     * @return string
     */
    public function getChallengeName()
    {
        return $this->challengeName;
    }

    /**
     * @param string $challengeName
     */
    public function setChallengeName($challengeName)
    {
        $this->challengeName = $challengeName;
    }

    /**
     * @return array
     */
    public function getChallengeParameters()
    {
        return $this->challengeParameters;
    }

    /**
     * @param array $challengeParameters
     */
    public function setChallengeParameters($challengeParameters)
    {
        $this->challengeParameters = $challengeParameters;
    }

    /**
     * @return array
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * @param array $response
     */
    public function setResponse($response)
    {
        $this->response = $response;
    }

    /**
     * @return string
     */
    public function getSession()
    {
        return $this->session;
    }

    /**
     * @param string $session
     */
    public function setSession($session)
    {
        $this->session = $session;
    }
}