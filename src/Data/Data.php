<?php

namespace Corviz\Jwt\Data;

use Exception;
use InvalidArgumentException;
use JsonSerializable;

abstract class Data implements JsonSerializable
{
    /**
     * @var array
     */
    private $data = [];

    /**
     * @var array
     */
    private $validators = [];

    /**
     * @param array $data
     *
     * @return static
     */
    public static function fromArray(array $data)
    {
        $intance = new static();
        $intance->setData($data);

        return $intance;
    }

    /**
     * @param string $json
     *
     * @return static
     */
    public static function fromJson(string $json)
    {
        $data = json_decode($json, true);

        if ((!$data && json_last_error()) || ! is_array($data)) {
            throw new InvalidArgumentException("Invalid json format provided");
        }

        return static::fromArray($data);
    }

    /**
     * @param mixed $index
     * @param mixed $validatorClass
     *
     * @return void
     * @throws Exception
     */
    public function assignValidator($index, $validatorClass)
    {
        $validator = null;

        if (is_string($validatorClass)) {
            $validator = new $validatorClass;
        }

        if (is_object($validatorClass) && ($validatorClass instanceof Validator)) {
            $validator = $validatorClass;
        }

        if (!($validator instanceof Validator)) {
            throw new Exception("Trying to assign invalid validator at $index");
        }

        $this->validators[$index] = $validator;
    }

    /**
     * @return array
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * @param array $data
     */
    public function setData(array $data): void
    {
        $this->data = $data;
    }

    /**
     * @param mixed $index
     * @param mixed $value
     *
     * @return $this
     */
    public function set($index, $value)
    {
        $this->data[$index] = $value;

        return $this;
    }

    /**
     * @param mixed $index
     *
     * @return $this
     */
    public function remove($index)
    {
        unset($this->data[$index]);

        return $this;
    }

    /**
     * @param mixed $index
     *
     * @return bool
     */
    public function has($index) : bool
    {
        return isset($this->data[$index]);
    }

    /**
     * @param mixed $index
     *
     * @return mixed
     */
    public function get($index)
    {
        return $this->data[$index];
    }

    /**
     * @return false|mixed|string
     */
    public function jsonSerialize()
    {
        return json_encode($this->data);
    }

    /**
     * Returns TRUE when content is valid. FALSE otherwise.
     *
     * @return bool
     */
    public function isValid() : bool
    {
        $valid = true;

        $validators = array_intersect_key($this->validators, $this->data);

        foreach ($validators as $index => $validator)
        {
            /* @var $validator Validator */
            if (!$validator->validate($this->data[$index])) {
                $valid = false;
                break;
            }
        }

        return $valid;
    }
}
